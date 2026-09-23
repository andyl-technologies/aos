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
    ) -> Result<VerifiedPhysicalCatalogSnapshotV1, StorageStateError> {
        let provider = Self::load(journal, key_id, secret)?;
        let head = provider.head.ok_or(StorageStateError::InvalidTransition)?;
        VerifiedPhysicalCatalogSnapshotV1::from_state(head)
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

    pub(crate) fn atomic_group_member_guids(&self, operation: [u8; 16]) -> Option<&[u64]> {
        self.transitions
            .get(&operation)
            .and_then(|transition| transition.group.as_ref())
            .map(|group| group.member_guids.as_slice())
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
        if catalog.format_version() != FORMAT_VERSION {
            return Err(StorageStateError::InvalidTransition);
        }
        if predecessor.binding.generation().checked_add(1) != Some(catalog.generation()) {
            return Err(StorageStateError::InvalidTransition);
        }
        ingest_plan_inputs(&mut predecessor.wire.clone(), catalog.plan(), false)?;

        let worst_case_guid = capture_guid(catalog.plan()).then_some(u64::MAX);
        let worst_case_zfs_observation = ObjectDigest::from_bytes([u8::MAX; 32]);
        let worst_case_metadata = worst_case_guid
            .map(|guid| {
                maximum_snapshot_metadata_record(
                    operation_id,
                    request_digest,
                    mutation_digest,
                    catalog,
                    guid,
                    worst_case_zfs_observation,
                )
            })
            .transpose()?
            .flatten();
        let worst_case_state = predecessor.apply_with_snapshot_metadata(
            operation_id,
            catalog,
            worst_case_guid,
            worst_case_metadata,
        )?;
        let worst_case_observation = match worst_case_metadata {
            Some(metadata) => snapshot_commit_observation_digest(
                worst_case_zfs_observation,
                metadata.record_digest(),
            )
            .map_err(|_| StorageStateError::InvalidValue)?,
            None => worst_case_zfs_observation,
        };
        let maximum_transition_bytes = encoded_transition_size(
            operation_id,
            mutation_digest,
            catalog,
            &predecessor,
            &worst_case_state,
            worst_case_guid,
            worst_case_observation,
            key_id,
            secret,
        )?;
        if maximum_transition_bytes > MAXIMUM_RECORD_BYTES {
            return Err(StorageStateError::InvalidValue);
        }

        let payload = ReservationPayload {
            operation_id,
            request_digest: *request_digest.as_bytes(),
            mutation_digest: *mutation_digest.as_bytes(),
            catalog: catalog.binding().into(),
            catalog_bytes_digest: digest_bytes(catalog.canonical_bytes()),
            predecessor: predecessor.binding.into(),
            maximum_transition_bytes: u32::try_from(maximum_transition_bytes)
                .map_err(|_| StorageStateError::InvalidValue)?,
            group_program: None,
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

    pub(crate) fn group_effect_capacity_records(operation_id: [u8; 16]) -> Vec<JournalRecord> {
        vec![
            JournalRecord::put(
                RecordNamespace::StorageCatalogTransition,
                operation_id.to_vec(),
                vec![0; MAXIMUM_RECORD_BYTES],
            ),
            JournalRecord::put(
                RecordNamespace::StorageCatalogHead,
                HEAD_KEY.to_vec(),
                vec![0; MAXIMUM_HEAD_BYTES],
            ),
        ]
    }

    pub(crate) fn reserve_atomic_group(
        &self,
        program: &crate::DormantAtomicDatasetSnapshotV1,
        request_digest: ObjectDigest,
        key_id: [u8; 16],
        secret: &[u8; 32],
    ) -> Result<CatalogReservation, StorageStateError> {
        let operation_id = program.operation();
        if request_digest.as_bytes() == &[0; 32]
            || self.reservations.contains_key(&operation_id)
            || self
                .reservations
                .keys()
                .any(|reserved| !self.transitions.contains_key(reserved))
            || self.genesis_binding().map(CatalogBindingV1::digest)
                != Some(program.catalog_source())
        {
            return Err(StorageStateError::InvalidTransition);
        }
        let predecessor = self
            .head
            .as_ref()
            .filter(|head| {
                head.binding.generation() == program.catalog_generation()
                    && head.binding.digest() == program.catalog_head()
            })
            .cloned()
            .ok_or(StorageStateError::InvalidTransition)?;
        let next_generation = predecessor
            .binding
            .generation()
            .checked_add(1)
            .ok_or(StorageStateError::InvalidTransition)?;
        let catalog = CatalogBindingV1::from_publisher(next_generation, program.commitment())
            .map_err(|_| StorageStateError::InvalidTransition)?;
        let program_bytes = program
            .canonical_bytes()
            .map_err(|_| StorageStateError::InvalidValue)?;
        let occupied = predecessor
            .wire
            .roots
            .iter()
            .map(|root| root.guid)
            .chain(predecessor.wire.datasets.iter().map(|dataset| dataset.guid))
            .chain(
                predecessor
                    .wire
                    .snapshots
                    .iter()
                    .map(|snapshot| snapshot.guid),
            )
            .chain(
                predecessor
                    .wire
                    .tombstones
                    .iter()
                    .map(|tombstone| tombstone.guid),
            )
            .collect::<std::collections::BTreeSet<_>>();
        let worst_case_guids = (1..=u64::MAX)
            .rev()
            .filter(|guid| !occupied.contains(guid))
            .take(program.member_count())
            .collect::<Vec<_>>();
        let worst_case_result =
            predecessor.apply_atomic_snapshot_group(program, &worst_case_guids)?;
        let worst_case = group_transition_payload(
            program,
            &predecessor,
            &worst_case_result,
            ObjectDigest::from_bytes([u8::MAX; 32]),
            &worst_case_guids,
        );
        // Remaining digest/MAC JSON width varies with the actual GUIDs; leave
        // a conservative fixed margin before crossing the backend boundary.
        if encode_transition_payload(&worst_case, key_id, secret)?.len()
            > MAXIMUM_RECORD_BYTES - 4096
        {
            return Err(StorageStateError::InvalidValue);
        }
        let payload = ReservationPayload {
            operation_id,
            request_digest: *request_digest.as_bytes(),
            mutation_digest: *program.commitment().as_bytes(),
            catalog: catalog.into(),
            catalog_bytes_digest: digest_bytes(&program_bytes),
            predecessor: predecessor.binding.into(),
            maximum_transition_bytes: MAXIMUM_RECORD_BYTES as u32,
            group_program: Some(*program.commitment().as_bytes()),
        };
        let bytes = encode_reservation_payload(&payload, &predecessor, key_id, secret)?;
        Ok(CatalogReservation {
            payload,
            bytes,
            predecessor,
        })
    }

    pub(crate) fn prepare_atomic_group_transition(
        &self,
        program: &crate::DormantAtomicDatasetSnapshotV1,
        request_digest: ObjectDigest,
        observation: ObjectDigest,
        member_guids: &[u64],
        key_id: [u8; 16],
        secret: &[u8; 32],
    ) -> Result<PreparedCatalogTransition, StorageStateError> {
        let reservation = self
            .reservations
            .get(&program.operation())
            .ok_or(StorageStateError::InvalidTransition)?;
        if self.transitions.contains_key(&program.operation())
            || reservation.payload.group_program != Some(*program.commitment().as_bytes())
            || reservation.payload.request_digest != *request_digest.as_bytes()
            || reservation.payload.catalog_bytes_digest
                != digest_bytes(
                    &program
                        .canonical_bytes()
                        .map_err(|_| StorageStateError::InvalidValue)?,
                )
            || self.head_binding() != Some(reservation.predecessor.binding)
            || crate::lifecycle_atomic_snapshot::atomic_snapshot_observation_digest(
                program,
                member_guids,
            )
            .map_err(|_| StorageStateError::InvalidValue)?
                != observation
        {
            return Err(StorageStateError::InvalidTransition);
        }
        let result_state = reservation
            .predecessor
            .apply_atomic_snapshot_group(program, member_guids)?;
        let transition = group_transition_payload(
            program,
            &reservation.predecessor,
            &result_state,
            observation,
            member_guids,
        );
        let transition_bytes = encode_transition_payload(&transition, key_id, secret)?;
        let digest = transition_digest(&transition)?;
        let head_bytes = encode_head_payload(
            &HeadPayload {
                binding: result_state.binding.into(),
                operation_id: Some(program.operation()),
                transition_digest: Some(*digest.as_bytes()),
                genesis_state: None,
            },
            key_id,
            secret,
        )?;
        if head_bytes.len() > MAXIMUM_HEAD_BYTES {
            return Err(StorageStateError::InvalidValue);
        }
        Ok(PreparedCatalogTransition {
            operation_id: program.operation(),
            snapshot_metadata: None,
            transition,
            transition_bytes,
            head_bytes,
            result_state,
        })
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn aborted_reservation_record(
        &self,
        operation_id: [u8; 16],
        request_digest: ObjectDigest,
        mutation_digest: ObjectDigest,
        catalog: &ResolvedCatalogCommitmentV1,
        key_id: [u8; 16],
        secret: &[u8; 32],
    ) -> Result<JournalRecord, StorageStateError> {
        let reservation = self
            .reservations
            .get(&operation_id)
            .ok_or(StorageStateError::InvalidTransition)?;
        if self.transitions.contains_key(&operation_id)
            || reservation.payload.request_digest != *request_digest.as_bytes()
            || reservation.payload.mutation_digest != *mutation_digest.as_bytes()
            || reservation.payload.catalog != catalog.binding().into()
            || reservation.payload.catalog_bytes_digest != digest_bytes(catalog.canonical_bytes())
            || self
                .head
                .as_ref()
                .is_none_or(|head| head.binding != reservation.predecessor.binding)
        {
            return Err(StorageStateError::InvalidTransition);
        }
        validate_reserved_transition_bound(reservation, catalog, key_id, secret)?;

        Ok(JournalRecord::delete(
            RecordNamespace::StorageCatalogReservation,
            operation_id.to_vec(),
        ))
    }

    pub(crate) fn install_abort(&mut self, operation_id: [u8; 16]) {
        let removed = self.reservations.remove(&operation_id);
        debug_assert!(removed.is_some());
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_transition(
        &self,
        operation_id: [u8; 16],
        mutation_digest: ObjectDigest,
        catalog: &ResolvedCatalogCommitmentV1,
        object_guid: Option<u64>,
        zfs_observation_digest: ObjectDigest,
        key_id: [u8; 16],
        secret: &[u8; 32],
    ) -> Result<PreparedCatalogTransition, StorageStateError> {
        self.prepare_transition_with_supplement(
            operation_id,
            mutation_digest,
            catalog,
            object_guid,
            zfs_observation_digest,
            CatalogCommitSupplementV1::None,
            key_id,
            secret,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_transition_with_supplement(
        &self,
        operation_id: [u8; 16],
        mutation_digest: ObjectDigest,
        catalog: &ResolvedCatalogCommitmentV1,
        object_guid: Option<u64>,
        zfs_observation_digest: ObjectDigest,
        supplement: CatalogCommitSupplementV1,
        key_id: [u8; 16],
        secret: &[u8; 32],
    ) -> Result<PreparedCatalogTransition, StorageStateError> {
        let reservation = self
            .reservations
            .get(&operation_id)
            .ok_or(StorageStateError::InvalidTransition)?;
        let snapshot_metadata = match (catalog.plan(), supplement) {
            (
                CatalogPlanV1::Snapshot { source, .. },
                CatalogCommitSupplementV1::Snapshot(evidence),
            ) => {
                let metadata = evidence.metadata();
                let snapshot_guid = object_guid.ok_or(StorageStateError::InvalidValue)?;
                validate_snapshot_metadata_record(
                    metadata,
                    operation_id,
                    snapshot_guid,
                    source.guid(),
                    Some(source.storage_handle()),
                )?;
                if metadata.request_digest()
                    != ObjectDigest::from_bytes(reservation.payload.request_digest)
                    || metadata.mutation_digest() != mutation_digest
                    || metadata.request_catalog() != catalog.binding()
                    || metadata.zfs_observation_digest() != zfs_observation_digest
                {
                    return Err(StorageStateError::AuthorityLinkMismatch);
                }
                Some(metadata)
            }
            (CatalogPlanV1::Snapshot { .. }, CatalogCommitSupplementV1::None)
            | (_, CatalogCommitSupplementV1::Snapshot(_)) => {
                return Err(StorageStateError::InvalidTransition);
            }
            (_, CatalogCommitSupplementV1::None) => None,
        };
        let observation_digest = match snapshot_metadata {
            Some(metadata) => {
                snapshot_commit_observation_digest(zfs_observation_digest, metadata.record_digest())
                    .map_err(|_| StorageStateError::InvalidValue)?
            }
            None => zfs_observation_digest,
        };
        self.prepare_transition_inner(
            operation_id,
            mutation_digest,
            catalog,
            object_guid,
            observation_digest,
            snapshot_metadata,
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
        metadata: CheckedSnapshotMetadataRecordV1,
        key_id: [u8; 16],
        secret: &[u8; 32],
    ) -> Result<PreparedCatalogTransition, StorageStateError> {
        self.prepare_transition_with_supplement(
            operation_id,
            mutation_digest,
            catalog,
            Some(object_guid),
            observation_digest,
            CatalogCommitSupplementV1::Snapshot(
                crate::snapshot_metadata::SnapshotCommitEvidenceV1::from_checked_record(metadata),
            ),
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
        snapshot_metadata: Option<CheckedSnapshotMetadataRecordV1>,
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
            snapshot_metadata,
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
            snapshot_metadata,
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
        if record_version != STORAGE_RECORD_VERSION {
            return Err(StorageStateError::CorruptRecord);
        }

        if phase == DurableStoragePhase::Aborted {
            return if reservation.is_none() && transition.is_none() && result_catalog.is_none() {
                Ok(None)
            } else {
                Err(StorageStateError::CorruptRecord)
            };
        }

        let reservation = reservation.ok_or(StorageStateError::CorruptRecord)?;
        if reservation.payload.request_digest != *request_digest.as_bytes()
            || reservation.payload.mutation_digest != *mutation_digest.as_bytes()
            || reservation.payload.catalog != catalog.binding().into()
            || reservation.payload.catalog_bytes_digest != digest_bytes(catalog.canonical_bytes())
            || reservation.payload.group_program.is_some()
        {
            return Err(StorageStateError::CorruptRecord);
        }
        validate_reserved_transition_bound(reservation, catalog, key_id, secret)?;

        match (phase, transition, result_catalog) {
            (DurableStoragePhase::Prepared | DurableStoragePhase::Ambiguous, None, None) => {
                Ok(None)
            }
            (DurableStoragePhase::Committed, Some(transition), Some(result_catalog)) => {
                let snapshot_metadata = match (catalog.plan(), transition.object_guid) {
                    (CatalogPlanV1::Snapshot { destination, .. }, Some(guid)) => transition
                        .result_state
                        .snapshot_metadata
                        .get(&(destination.name().to_owned(), guid))
                        .map(|wire| {
                            validate_snapshot_metadata_wire(
                                wire,
                                guid,
                                destination.dataset().guid(),
                                Some(destination.dataset().storage_handle()),
                            )
                        })
                        .transpose()?,
                    _ => None,
                };
                if snapshot_metadata.is_some_and(|metadata| {
                    metadata.operation_id() != operation_id
                        || metadata.request_digest() != request_digest
                        || metadata.mutation_digest() != mutation_digest
                        || metadata.request_catalog() != catalog.binding()
                }) {
                    return Err(StorageStateError::CorruptRecord);
                }
                let result_state = reservation.predecessor.apply_with_snapshot_metadata(
                    operation_id,
                    catalog,
                    transition.object_guid,
                    snapshot_metadata,
                )?;
                let expected_observation_digest = match snapshot_metadata {
                    Some(metadata) => snapshot_commit_observation_digest(
                        metadata.zfs_observation_digest(),
                        metadata.record_digest(),
                    )
                    .map_err(|_| StorageStateError::CorruptRecord)?,
                    None => ObjectDigest::from_bytes(transition.observation_digest),
                };
                if transition.operation_id != operation_id
                    || transition.group.is_some()
                    || transition.mutation_digest != *mutation_digest.as_bytes()
                    || transition.catalog != catalog.binding().into()
                    || transition.predecessor != reservation.payload.predecessor
                    || transition.result != result_state.binding.into()
                    || transition.result_state != result_state
                    || result_catalog != result_state.binding
                    || transition.observation_digest != *expected_observation_digest.as_bytes()
                {
                    return Err(StorageStateError::CorruptRecord);
                }
                Ok(Some(CatalogTransitionEvidence {
                    result_catalog,
                    observation_digest: ObjectDigest::from_bytes(transition.observation_digest),
                    object_guid: transition.object_guid,
                    snapshot_metadata,
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

    pub(crate) fn validate_atomic_group_record(
        &self,
        program: &crate::DormantAtomicDatasetSnapshotV1,
        request_digest: ObjectDigest,
        committed: Option<(ObjectDigest, CatalogBindingV1)>,
    ) -> Result<(), StorageStateError> {
        let reservation = self.reservations.get(&program.operation());
        let transition = self.transitions.get(&program.operation());
        if program.format_version() == 1 {
            return if reservation.is_none() && transition.is_none() {
                Ok(())
            } else {
                Err(StorageStateError::CorruptRecord)
            };
        }
        let reservation = reservation.ok_or(StorageStateError::CorruptRecord)?;
        let program_bytes = program
            .canonical_bytes()
            .map_err(|_| StorageStateError::CorruptRecord)?;
        if self.genesis_binding().map(CatalogBindingV1::digest) != Some(program.catalog_source())
            || reservation.payload.group_program != Some(*program.commitment().as_bytes())
            || reservation.payload.request_digest != *request_digest.as_bytes()
            || reservation.payload.mutation_digest != *program.commitment().as_bytes()
            || reservation.payload.catalog_bytes_digest != digest_bytes(&program_bytes)
            || reservation.payload.predecessor != reservation.predecessor.binding.into()
            || reservation.predecessor.binding.generation() != program.catalog_generation()
            || reservation.predecessor.binding.digest() != program.catalog_head()
        {
            return Err(StorageStateError::CorruptRecord);
        }
        match (committed, transition) {
            (None, None) => Ok(()),
            (Some((observation, post_head)), Some(transition)) => {
                let group = transition
                    .group
                    .as_ref()
                    .ok_or(StorageStateError::CorruptRecord)?;
                let expected_observation =
                    crate::lifecycle_atomic_snapshot::atomic_snapshot_observation_digest(
                        program,
                        &group.member_guids,
                    )
                    .map_err(|_| StorageStateError::CorruptRecord)?;
                let result = reservation
                    .predecessor
                    .apply_atomic_snapshot_group(program, &group.member_guids)?;
                if group.program != *program.commitment().as_bytes()
                    || transition.operation_id != program.operation()
                    || transition.observation_digest != *observation.as_bytes()
                    || expected_observation != observation
                    || transition.result_state != result
                    || transition.result != result.binding.into()
                    || post_head != result.binding
                {
                    return Err(StorageStateError::CorruptRecord);
                }
                Ok(())
            }
            _ => Err(StorageStateError::CorruptRecord),
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

fn group_transition_payload(
    program: &crate::DormantAtomicDatasetSnapshotV1,
    predecessor: &PhysicalCatalogState,
    result_state: &PhysicalCatalogState,
    observation: ObjectDigest,
    member_guids: &[u64],
) -> TransitionPayload {
    TransitionPayload {
        operation_id: program.operation(),
        mutation_digest: *program.commitment().as_bytes(),
        catalog: BindingWire {
            generation: result_state.binding.generation(),
            digest: *program.commitment().as_bytes(),
        },
        predecessor: predecessor.binding.into(),
        result: result_state.binding.into(),
        observation_digest: *observation.as_bytes(),
        object_guid: None,
        group: Some(GroupTransitionEvidence {
            program: *program.commitment().as_bytes(),
            member_guids: member_guids.to_vec(),
        }),
        result_state: result_state.clone(),
    }
}
