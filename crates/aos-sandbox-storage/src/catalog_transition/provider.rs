//! Durable physical-catalog provider and authenticated journal recovery.

use super::*;

#[derive(Debug)]
pub(crate) struct StorageCatalogTransitionProvider {
    pub(super) genesis: Option<CatalogBindingV1>,
    pub(super) head: Option<PhysicalCatalogState>,
    pub(super) reservations: BTreeMap<[u8; 16], CatalogReservation>,
    pub(super) transitions: BTreeMap<[u8; 16], TransitionPayload>,
}

impl StorageCatalogTransitionProvider {
    /// Reloads and projects only a fully authenticated durable catalog head.
    ///
    /// This is deliberately an associated journal operation rather than a
    /// method on an in-memory provider: values installed after a prepared
    /// commit cannot become resolver authority until journal recovery verifies
    /// the complete chain again.
    pub(crate) fn load_resolver_snapshot(
        journal: &Journal,
        key_id: [u8; 16],
        secret: &[u8; 32],
    ) -> Result<VerifiedPhysicalCatalogSnapshotV2, StorageStateError> {
        let provider = Self::load(journal, key_id, secret)?;
        let head = provider.head.ok_or(StorageStateError::InvalidTransition)?;
        VerifiedPhysicalCatalogSnapshotV2::from_state(head)
    }

    pub(crate) fn load(
        journal: &Journal,
        key_id: [u8; 16],
        secret: &[u8; 32],
    ) -> Result<Self, StorageStateError> {
        let mut reservations = BTreeMap::new();
        for (record_key, bytes) in journal.records(RecordNamespace::StorageCatalogReservation) {
            let (payload, predecessor) = decode_reservation_payload(bytes, key_id, secret)?;
            if record_key != payload.operation_id {
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
            let payload = decode_transition_payload(bytes, key_id, secret)?;
            if record_key != payload.operation_id {
                return Err(StorageStateError::CorruptRecord);
            }
            if transitions.insert(payload.operation_id, payload).is_some() {
                return Err(StorageStateError::CorruptRecord);
            }
        }

        let head_payload = match journal.get(RecordNamespace::StorageCatalogHead, HEAD_KEY) {
            Some(bytes) => {
                let payload = decode_head_payload(bytes, key_id, secret)?;
                validate_head(&payload, &transitions)?;
                Some(payload)
            }
            None if transitions.is_empty() && reservations.is_empty() => None,
            None => return Err(StorageStateError::CorruptRecord),
        };
        let head = match head_payload.as_ref() {
            Some(payload) => match (&payload.genesis_state, payload.operation_id) {
                (Some(state), None) => Some(state.clone()),
                (None, Some(operation_id)) => {
                    let transition = transitions
                        .get(&operation_id)
                        .ok_or(StorageStateError::CorruptRecord)?;
                    Some(transition.result_state.clone())
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
            format: match state.format {
                PhysicalStateFormatV1::LegacyV1 => CatalogRecordFormatV1::LegacyV1,
                PhysicalStateFormatV1::ExecutionV2 => CatalogRecordFormatV1::ExecutionV2,
            },
            binding: state.binding.into(),
            operation_id: None,
            transition_digest: None,
            genesis_state: Some(state.clone()),
        };
        let head_bytes = encode_head_payload(&payload, key_id, secret)?;
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
        let format = match (predecessor.format, catalog.format_version()) {
            (PhysicalStateFormatV1::LegacyV1, 2) => CatalogRecordFormatV1::LegacyV1,
            (PhysicalStateFormatV1::LegacyV1 | PhysicalStateFormatV1::ExecutionV2, 3) => {
                CatalogRecordFormatV1::ExecutionV2
            }
            (PhysicalStateFormatV1::ExecutionV2, 2) => {
                return Err(StorageStateError::InvalidTransition);
            }
            _ => return Err(StorageStateError::InvalidTransition),
        };
        if predecessor.binding.generation().checked_add(1) != Some(catalog.generation()) {
            return Err(StorageStateError::InvalidTransition);
        }
        ingest_plan_inputs(&mut predecessor.wire.clone(), catalog.plan(), false)?;

        let worst_case_guid = capture_guid(catalog.plan()).then_some(u64::MAX);
        let worst_case_state = predecessor.apply_with_snapshot_metadata(
            operation_id,
            catalog,
            worst_case_guid,
            worst_case_guid
                .map(|guid| maximum_snapshot_root_metadata_wire(catalog, guid))
                .transpose()?
                .flatten(),
        )?;
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
            format,
            operation_id,
            request_digest: *request_digest.as_bytes(),
            mutation_digest: *mutation_digest.as_bytes(),
            catalog: catalog.binding().into(),
            catalog_bytes_digest: digest_bytes(catalog.canonical_bytes()),
            predecessor: predecessor.binding.into(),
            maximum_transition_bytes: u32::try_from(maximum_transition_bytes)
                .map_err(|_| StorageStateError::InvalidValue)?,
        };
        let bytes = encode_reservation_payload(&payload, &predecessor, key_id, secret)?;
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
        self.prepare_transition_inner(
            operation_id,
            mutation_digest,
            catalog,
            object_guid,
            observation_digest,
            None,
            key_id,
            secret,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_transition_with_snapshot_metadata_for_test(
        &self,
        operation_id: [u8; 16],
        mutation_digest: ObjectDigest,
        catalog: &ResolvedCatalogCommitmentV1,
        object_guid: u64,
        observation_digest: ObjectDigest,
        metadata: CheckedSnapshotRootMetadataRecordV1,
        key_id: [u8; 16],
        secret: &[u8; 32],
    ) -> Result<PreparedCatalogTransition, StorageStateError> {
        let metadata = SnapshotRootMetadataWireV1 {
            version: 1,
            record: metadata.canonical_bytes().to_vec(),
            record_digest: *metadata.record_digest().as_bytes(),
            content_commitment: *metadata.content_commitment().as_bytes(),
        };
        self.prepare_transition_inner(
            operation_id,
            mutation_digest,
            catalog,
            Some(object_guid),
            observation_digest,
            Some(metadata),
            key_id,
            secret,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_transition_inner(
        &self,
        operation_id: [u8; 16],
        mutation_digest: ObjectDigest,
        catalog: &ResolvedCatalogCommitmentV1,
        object_guid: Option<u64>,
        observation_digest: ObjectDigest,
        snapshot_root_metadata: Option<SnapshotRootMetadataWireV1>,
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
        let result_state = reservation.predecessor.apply_with_snapshot_metadata(
            operation_id,
            catalog,
            object_guid,
            snapshot_root_metadata,
        )?;
        let transition = transition_payload(
            operation_id,
            mutation_digest,
            catalog,
            &reservation.predecessor,
            &result_state,
            object_guid,
            observation_digest,
        )?;
        let transition_bytes = encode_transition_payload(&transition, key_id, secret)?;
        if transition_bytes.len() > reservation.payload.maximum_transition_bytes as usize
            || transition_bytes.len() > MAXIMUM_RECORD_BYTES
        {
            return Err(StorageStateError::InvalidTransition);
        }
        let transition_digest = transition_digest(&transition)?;
        let head_payload = HeadPayload {
            format: transition.format,
            binding: result_state.binding.into(),
            operation_id: Some(operation_id),
            transition_digest: Some(*transition_digest.as_bytes()),
            genesis_state: None,
        };
        let head_bytes = encode_head_payload(&head_payload, key_id, secret)?;
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
                let result_state = reservation.predecessor.apply_with_snapshot_metadata(
                    operation_id,
                    catalog,
                    transition.object_guid,
                    match (catalog.plan(), transition.object_guid) {
                        (CatalogPlanV1::Snapshot { destination, .. }, Some(guid)) => transition
                            .result_state
                            .snapshot_root_metadata
                            .get(&(destination.name().to_owned(), guid))
                            .cloned(),
                        _ => None,
                    },
                )?;
                if transition.operation_id != operation_id
                    || transition.mutation_digest != *mutation_digest.as_bytes()
                    || transition.catalog != catalog.binding().into()
                    || transition.predecessor != reservation.payload.predecessor
                    || transition.result != result_state.binding.into()
                    || transition.result_state != result_state
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
