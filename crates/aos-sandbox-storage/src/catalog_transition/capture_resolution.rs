//! Binds the dedicated Capture row recipe to the actual fresh signed issuer.
//!
//! The existing catalog MAC chain records historical physical facts. This
//! recipe is constructed only beside the actual noncopyable fresh424 owner;
//! decoded catalog/attempt rows cannot reconstruct it or re-enter create.
//! Native create/readback, State persistence and same-F custody stay separate.

use super::*;
use execution_capture::CaptureDatasetRequirementV1;
use crate::execution_output::FreshCaptureCreateCommitV3;

const RESOLUTION_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-catalog-resolution.v3\0";
const MUTATION_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-catalog-mutation.v3\0";

pub(crate) struct CaptureCatalogResolutionV3 {
    requirement: CaptureDatasetRequirementV1,
    binding: CatalogBindingV1,
    predecessor: CatalogBindingV1,
    request_digest: ObjectDigest,
    mutation_digest: ObjectDigest,
    bytes: Vec<u8>,
    operation: CaptureCatalogOperationWireV3,
}

impl CaptureCatalogResolutionV3 {
    pub(crate) fn requirement_v3(&self) -> &CaptureDatasetRequirementV1 {
        &self.requirement
    }

    pub(crate) fn request_digest_v3(&self) -> ObjectDigest { self.request_digest }
    pub(crate) fn mutation_digest_v3(&self) -> ObjectDigest { self.mutation_digest }
    pub(crate) fn binding_v3(&self) -> CatalogBindingV1 { self.binding }
    pub(crate) fn predecessor_v3(&self) -> CatalogBindingV1 { self.predecessor }

    pub(crate) fn operation_v3(&self) -> [u8; 16] {
        *self.requirement.storage_create_operation().as_bytes()
    }
}

impl StorageCatalogTransitionProvider {
    pub(crate) fn prepare_capture_resolution_v3(
        &self,
        fresh: &FreshCaptureCreateCommitV3,
    ) -> Result<CaptureCatalogResolutionV3, StorageStateError> {
        let predecessor = self.head_binding().ok_or(StorageStateError::InvalidTransition)?;
        let generation = predecessor.generation().checked_add(1)
            .ok_or(StorageStateError::InvalidTransition)?;
        let (_, _, _, durable, _, _, _, requirement, policy) = fresh.native_parts_v3();
        let admitted = fresh.admitted_v3();
        let source = admitted.source_v3();
        let request_digest = admitted.lifetime_v3().admission_v3().effect.transport_request_digest();
        let policy_digest = requirement.attempt_policy_digest(
            policy.metadata_headroom_bytes(), policy.minimum_remaining_bytes(),
        );
        let operation = CaptureCatalogOperationWireV3 {
            magic: "AOSCCR03".to_owned(), version: 3,
            source: source.canonical_bytes_v2().to_vec(),
            durable_attempt: *durable.as_bytes(), request: *request_digest.as_bytes(),
            predecessor: predecessor.into(),
            root: requirement.root().into(),
            domains: requirement.planned_dataset().domains().into(),
            policy: *policy_digest.as_bytes(),
        };
        // The same canonical payload enters the reservation digest and an
        // authenticated operation row. Cold recovery replays this dedicated
        // recipe and cannot treat its transition as an orphan ordinary job.
        let bytes = serde_json::to_vec(&operation)
            .map_err(|_| StorageStateError::InvalidValue)?;
        let digest = ObjectDigest::from_bytes(Sha256::new()
            .chain_update(RESOLUTION_DOMAIN).chain_update(&bytes).finalize().into());
        let binding = CatalogBindingV1::from_publisher(generation, digest)
            .map_err(|_| StorageStateError::InvalidValue)?;
        let mutation_digest = ObjectDigest::from_bytes(Sha256::new()
            .chain_update(MUTATION_DOMAIN).chain_update(digest.as_bytes())
            .chain_update(request_digest.as_bytes()).finalize().into());
        Ok(CaptureCatalogResolutionV3 {
            requirement: requirement.clone(), binding, predecessor,
            request_digest, mutation_digest, bytes, operation,
        })
    }
}

#[derive(Clone, Copy)]
pub(super) enum CatalogResolutionRecipeV3<'a> {
    Ordinary(&'a ResolvedCatalogCommitmentV1),
    Capture(&'a CaptureCatalogResolutionV3),
}

impl<'a> CatalogResolutionRecipeV3<'a> {
    pub(super) fn binding(self) -> CatalogBindingV1 {
        match self { Self::Ordinary(catalog) => catalog.binding(), Self::Capture(capture) => capture.binding }
    }

    pub(super) fn generation(self) -> u64 { self.binding().generation() }

    pub(super) fn current_format(self) -> bool {
        match self { Self::Ordinary(catalog) => catalog.format_version() == FORMAT_VERSION, Self::Capture(_) => true }
    }

    pub(super) fn canonical_bytes(self) -> &'a [u8] {
        match self { Self::Ordinary(catalog) => catalog.canonical_bytes(), Self::Capture(capture) => &capture.bytes }
    }

    pub(super) fn captures_guid(self) -> bool {
        match self { Self::Ordinary(catalog) => capture_guid(catalog.plan()), Self::Capture(_) => true }
    }

    pub(super) fn ingest(self, wire: &mut PhysicalStateWire, operation: [u8; 16])
        -> Result<(), StorageStateError>
    {
        match self {
            Self::Ordinary(catalog) => ingest_plan_inputs(wire, catalog.plan(), false),
            Self::Capture(capture) => singular_application::validate_capture_inputs_v3(
                wire, operation, &capture.requirement,
            ),
        }
    }

    pub(super) fn snapshot_metadata(
        self,
        operation: [u8; 16],
        request: ObjectDigest,
        mutation: ObjectDigest,
        guid: u64,
        observed: ObjectDigest,
    ) -> Result<Option<CheckedSnapshotMetadataRecordV1>, StorageStateError> {
        match self {
            Self::Ordinary(catalog) => maximum_snapshot_metadata_record(operation, request, mutation, catalog, guid, observed),
            Self::Capture(_) => Ok(None),
        }
    }

    pub(super) fn application_shape(self, source: &PhysicalCatalogState)
        -> Result<(usize, usize), aos_sandbox_core::AccountingError>
    {
        match self {
            Self::Ordinary(catalog) => singular_application::shape(source, catalog),
            Self::Capture(capture) => singular_application::capture_shape_v3(source, &capture.requirement),
        }
    }

    pub(super) fn apply(
        self,
        source: &PhysicalCatalogState,
        operation: [u8; 16],
        guid: Option<u64>,
        metadata: Option<CheckedSnapshotMetadataRecordV1>,
        receiving: Option<&mut crate::state::encoding::StateEncodingContextV1<'_, '_, '_>>,
        physical: &mut CatalogPhysicalApplicationOriginalV1,
    ) -> Result<PhysicalCatalogState, StorageStateError> {
        match self {
            Self::Ordinary(catalog) => match receiving {
                Some(receiving) => physical.apply(source, operation, catalog, guid, metadata, Some(receiving)),
                None => source.apply_with_snapshot_metadata(operation, catalog, guid, metadata),
            },
            Self::Capture(capture) => {
                if metadata.is_some() || source.binding != capture.predecessor {
                    return Err(StorageStateError::InvalidTransition);
                }
                physical.apply_capture_v3(source, operation, &capture.requirement,
                    capture.binding, guid.ok_or(StorageStateError::InvalidValue)?, receiving)
            }
        }
    }

    pub(super) fn transition_variable_bytes(self) -> usize {
        match self {
            Self::Ordinary(catalog) => format::transition_variable_array_bytes(catalog),
            // One GUID and the same fixed digest/MAC array fields; no snapshot
            // metadata or group-member array is introduced by Capture.
            Self::Capture(_) => VARIABLE_TRANSITION_ARRAY_BYTES,
        }
    }
}

// This is a historical catalog operation, not a fresh worker capability. Its
// envelope and bounded canonical JSON parser are the existing catalog codec.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CaptureCatalogOperationWireV3 {
    magic: String,
    version: u16,
    source: Vec<u8>,
    durable_attempt: [u8; 32],
    request: [u8; 32],
    predecessor: BindingWire,
    root: RootWire,
    domains: DomainsWire,
    policy: [u8; 32],
}

const OPERATION_KEY_PREFIX: &[u8] = b"capture-catalog-v3:";

impl CaptureCatalogResolutionV3 {
    pub(crate) fn operation_record_receiving_v3(
        &self,
        key_id: [u8; 16],
        secret: &[u8; 32],
        receiving: &mut crate::state::encoding::StateEncodingContextV1<'_, '_, '_>,
    ) -> Result<JournalRecord, StorageStateError> {
        let bytes = format::encode_authenticated_receiving_v1(
            &self.operation, key_id, secret, Some(receiving),
        )?;
        let key = [OPERATION_KEY_PREFIX, self.operation_v3().as_slice()].concat();
        Ok(JournalRecord::put(RecordNamespace::Effect, key, bytes))
    }
}

impl CaptureCatalogOperationWireV3 {
    fn resolution_data_v3(&self) -> Result<CaptureCatalogResolutionV3, StorageStateError> {
        use aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2;
        if self.magic != "AOSCCR03" || self.version != 3
            || self.durable_attempt == [0; 32] || self.request == [0; 32]
        { return Err(StorageStateError::CorruptRecord); }
        let source = StorageCaptureGrantSourceV2::from_canonical_bytes_v2(&self.source)
            .map_err(|_| StorageStateError::CorruptRecord)?;
        let original = source.original_source_v1();
        let (allocation, headroom, floor) = original.space_policy();
        let root = ManagedDatasetRoot::from_catalog(
            &self.root.pool, &self.root.dataset_prefix, self.root.guid,
        ).map_err(|_| StorageStateError::CorruptRecord)?;
        let requirement = CaptureDatasetRequirementV1::new(
            original.settlement().execution(), original.settlement().create_operation(),
            original.output_claim_digest(), original.storage_create_operation(), root,
            domains_from_wire(self.domains)?, original.output_limits().0, allocation,
        ).map_err(|_| StorageStateError::CorruptRecord)?;
        if requirement.attempt_policy_digest(headroom, floor).as_bytes() != &self.policy {
            return Err(StorageStateError::CorruptRecord);
        }
        let predecessor = self.predecessor.binding()?;
        let generation = predecessor.generation().checked_add(1)
            .ok_or(StorageStateError::CorruptRecord)?;
        let bytes = serde_json::to_vec(self).map_err(|_| StorageStateError::CorruptRecord)?;
        let digest = ObjectDigest::from_bytes(Sha256::new()
            .chain_update(RESOLUTION_DOMAIN).chain_update(&bytes).finalize().into());
        let binding = CatalogBindingV1::from_publisher(generation, digest)
            .map_err(|_| StorageStateError::CorruptRecord)?;
        let request_digest = ObjectDigest::from_bytes(self.request);
        let mutation_digest = ObjectDigest::from_bytes(Sha256::new()
            .chain_update(MUTATION_DOMAIN).chain_update(digest.as_bytes())
            .chain_update(request_digest.as_bytes()).finalize().into());
        Ok(CaptureCatalogResolutionV3 {
            requirement, binding, predecessor, request_digest, mutation_digest,
            bytes, operation: self.clone(),
        })
    }
}

pub(super) fn load_operations_v3(
    journal: &Journal,
    key_id: [u8; 16],
    secret: &[u8; 32],
    reservations: &BTreeMap<[u8; 16], CatalogReservation>,
    transitions: &BTreeMap<[u8; 16], TransitionPayload>,
) -> Result<BTreeMap<[u8; 16], CaptureCatalogOperationWireV3>, StorageStateError> {
    let mut operations = BTreeMap::new();
    for (key, bytes) in journal.records(RecordNamespace::Effect) {
        let Some(id) = key.strip_prefix(OPERATION_KEY_PREFIX) else { continue; };
        let operation: CaptureCatalogOperationWireV3 =
            format::decode_authenticated(bytes, key_id, secret)?;
        let recipe = operation.resolution_data_v3()?;
        let id: [u8; 16] = id.try_into().map_err(|_| StorageStateError::CorruptRecord)?;
        let reservation = reservations.get(&id).ok_or(StorageStateError::CorruptRecord)?;
        if id != recipe.operation_v3()
            || reservation.payload.request_digest != *recipe.request_digest.as_bytes()
            || reservation.payload.mutation_digest != *recipe.mutation_digest.as_bytes()
            || reservation.payload.catalog != recipe.binding.into()
            || reservation.payload.predecessor != recipe.predecessor.into()
            || reservation.payload.catalog_bytes_digest != digest_bytes(&recipe.bytes)
        { return Err(StorageStateError::CorruptRecord); }
        if let Some(transition) = transitions.get(&id) {
            let guid = transition.object_guid.ok_or(StorageStateError::CorruptRecord)?;
            let mut physical = CatalogPhysicalApplicationOriginalV1::new();
            let expected = CatalogResolutionRecipeV3::Capture(&recipe).apply(
                &reservation.predecessor, id, Some(guid), None, None, &mut physical,
            )?;
            if transition.group.is_some()
                || transition.mutation_digest != *recipe.mutation_digest.as_bytes()
                || transition.catalog != recipe.binding.into()
                || transition.predecessor != recipe.predecessor.into()
                || transition.observation_digest == [0; 32]
                || transition.result != expected.binding.into()
                || transition.result_state != expected
            { return Err(StorageStateError::CorruptRecord); }
        }
        if operations.insert(id, operation).is_some() {
            return Err(StorageStateError::CorruptRecord);
        }
    }
    Ok(operations)
}

impl StorageCatalogTransitionProvider {
    pub(crate) fn install_capture_operation_v3(&mut self, resolution: &CaptureCatalogResolutionV3) {
        self.capture_operations.insert(resolution.operation_v3(), resolution.operation.clone());
    }
}
