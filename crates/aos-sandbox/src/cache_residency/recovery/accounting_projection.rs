//! Incremental reconstructed accounting and aggregate projections.

use super::*;

pub(super) fn aggregate_projections(
    subjects: &BTreeMap<ObjectDigest, CacheAtomicObjectPayloadV1>,
) -> Result<(ObjectDigest, ObjectDigest, ObjectDigest, ObjectDigest), RecoveryError> {
    Ok(ProjectionAccumulator::from_subjects(subjects)?.digests())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RecoveredAccountingProjection {
    node_quota: NodeCacheQuotaV1,
    project_quotas: BTreeMap<[u8; 16], ProjectCacheQuotaV1>,
    node_usage: CacheUsageV1,
    project_usage: BTreeMap<[u8; 16], CacheUsageV1>,
    reservation_projects: BTreeMap<[u8; 16], u64>,
}

impl RecoveredAccountingProjection {
    pub(super) fn from_subjects(
        global: &CacheGlobalRecoveryStateV1,
        subjects: &BTreeMap<ObjectDigest, CacheAtomicObjectPayloadV1>,
        limits: CacheRecoveryLimitsV1,
    ) -> Result<Self, RecoveryError> {
        let reservations = subjects
            .values()
            .map(|payload| payload.reservation.clone())
            .collect::<Vec<_>>();
        let mut active_pins = Vec::new();
        let mut released_pins = Vec::new();
        for payload in subjects.values() {
            if active_pins
                .len()
                .checked_add(released_pins.len())
                .and_then(|count| count.checked_add(payload.pins.len()))
                .and_then(|count| count.checked_add(payload.released_pins.len()))
                .is_none_or(|count| count > limits.maximum_records)
            {
                return Err(RecoveryError::Capacity);
            }
            active_pins.extend(payload.pins.iter().cloned());
            released_pins.extend(payload.released_pins.iter().cloned());
        }
        let accounting = CacheAccountingV1::replay(
            AccountingLimitsV1 {
                maximum_project_quotas: limits.maximum_subjects,
                maximum_reservations: limits.maximum_subjects,
            },
            global.node_quota,
            global.project_quotas.iter().copied(),
            reservations,
        )
        .map_err(|_| RecoveryError::PayloadMismatch)?;
        let pins = CachePinLedgerV1::replay(
            limits.maximum_records,
            global.pin_floor,
            active_pins,
            released_pins,
        )
        .map_err(|_| RecoveryError::PayloadMismatch)?;
        let (project_pin_usage, node_pin_usage) =
            pins.usage().map_err(|_| RecoveryError::PayloadMismatch)?;
        accounting
            .with_pin_usage(&project_pin_usage, node_pin_usage)
            .map_err(|_| RecoveryError::PayloadMismatch)?;

        let mut projection = Self {
            node_quota: global.node_quota,
            project_quotas: global
                .project_quotas
                .iter()
                .map(|quota| (*quota.project.as_bytes(), *quota))
                .collect(),
            node_usage: CacheUsageV1::default(),
            project_usage: BTreeMap::new(),
            reservation_projects: BTreeMap::new(),
        };
        for payload in subjects.values() {
            projection.add_payload(payload)?;
        }
        projection.validate()?;
        Ok(projection)
    }

    pub(super) fn replace(
        &mut self,
        previous: Option<&CacheAtomicObjectPayloadV1>,
        next: &CacheAtomicObjectPayloadV1,
        global: &CacheGlobalRecoveryStateV1,
    ) -> Result<(), RecoveryError> {
        if let Some(previous) = previous {
            self.remove_payload(previous)?;
        }
        self.add_payload(next)?;
        self.node_quota = global.node_quota;
        self.project_quotas = global
            .project_quotas
            .iter()
            .map(|quota| (*quota.project.as_bytes(), *quota))
            .collect();
        self.validate()
    }

    pub(super) fn add_payload(
        &mut self,
        payload: &CacheAtomicObjectPayloadV1,
    ) -> Result<(), RecoveryError> {
        let usage = payload_usage(payload)?;
        add_usage(&mut self.node_usage, usage)?;
        let reservation_usage = reservation_usage(&payload.reservation);
        let reservation_count = self
            .reservation_projects
            .entry(*payload.reservation.project.as_bytes())
            .or_default();
        *reservation_count = reservation_count
            .checked_add(1)
            .ok_or(RecoveryError::Capacity)?;
        add_usage(
            self.project_usage
                .entry(*payload.reservation.project.as_bytes())
                .or_default(),
            reservation_usage,
        )?;
        for pin in &payload.pins {
            add_usage(
                self.project_usage
                    .entry(*pin.project.as_bytes())
                    .or_default(),
                pin_usage(pin.kind),
            )?;
        }
        Ok(())
    }

    pub(super) fn remove_payload(
        &mut self,
        payload: &CacheAtomicObjectPayloadV1,
    ) -> Result<(), RecoveryError> {
        let usage = payload_usage(payload)?;
        subtract_usage(&mut self.node_usage, usage)?;
        let reservation_usage = reservation_usage(&payload.reservation);
        let project = self
            .project_usage
            .get_mut(payload.reservation.project.as_bytes())
            .ok_or(RecoveryError::PayloadMismatch)?;
        subtract_usage(project, reservation_usage)?;
        for pin in &payload.pins {
            let project = self
                .project_usage
                .get_mut(pin.project.as_bytes())
                .ok_or(RecoveryError::PayloadMismatch)?;
            subtract_usage(project, pin_usage(pin.kind))?;
        }
        let project_key = *payload.reservation.project.as_bytes();
        let reservation_count = self
            .reservation_projects
            .get_mut(&project_key)
            .ok_or(RecoveryError::PayloadMismatch)?;
        *reservation_count = reservation_count
            .checked_sub(1)
            .ok_or(RecoveryError::PayloadMismatch)?;
        if *reservation_count == 0 {
            self.reservation_projects.remove(&project_key);
        }
        let reservation_projects = &self.reservation_projects;
        self.project_usage.retain(|project, usage| {
            !usage_is_zero(*usage) || reservation_projects.contains_key(project)
        });
        Ok(())
    }

    pub(super) fn validate(&self) -> Result<(), RecoveryError> {
        if self
            .node_usage
            .physical_charged_bytes()
            .map_err(|_| RecoveryError::PayloadMismatch)?
            > self.node_quota.maximum_physical_bytes
            || self.node_usage.resident_objects > self.node_quota.maximum_resident_objects
            || self.node_usage.logical_pins > self.node_quota.maximum_logical_pins
            || self.node_usage.source_retentions > self.node_quota.maximum_source_retentions
            || self.node_usage.kernel_references > self.node_quota.maximum_kernel_references
            || self.node_usage.backing_registrations > self.node_quota.maximum_backing_registrations
        {
            return Err(RecoveryError::PayloadMismatch);
        }
        for (project, usage) in &self.project_usage {
            let quota = self
                .project_quotas
                .get(project)
                .ok_or(RecoveryError::PayloadMismatch)?;
            if usage
                .physical_charged_bytes()
                .map_err(|_| RecoveryError::PayloadMismatch)?
                > quota.maximum_charged_bytes
                || usage.logical_pins > quota.maximum_logical_pins
                || usage.source_retentions > quota.maximum_source_retentions
                || usage.kernel_references > quota.maximum_kernel_references
                || usage.backing_registrations > quota.maximum_backing_registrations
            {
                return Err(RecoveryError::PayloadMismatch);
            }
        }
        Ok(())
    }
}

pub(super) fn usage_is_zero(usage: CacheUsageV1) -> bool {
    usage == CacheUsageV1::default()
}

pub(super) fn payload_usage(
    payload: &CacheAtomicObjectPayloadV1,
) -> Result<CacheUsageV1, RecoveryError> {
    let mut usage = reservation_usage(&payload.reservation);
    for pin in &payload.pins {
        add_usage(&mut usage, pin_usage(pin.kind))?;
    }
    Ok(usage)
}

pub(super) fn reservation_usage(reservation: &CacheReservationV1) -> CacheUsageV1 {
    let mut usage = CacheUsageV1::default();
    match reservation.state {
        ReservationStateV1::Reserved | ReservationStateV1::Uncertain => {
            usage.reservation_bytes = reservation.reserved_bytes;
        }
        ReservationStateV1::Converted => {
            usage.residency_bytes = reservation.resident_bytes;
            usage.resident_objects = 1;
        }
        ReservationStateV1::Released | ReservationStateV1::Evicted => {}
    }
    usage
}

pub(super) fn pin_usage(kind: CachePinKindV1) -> CacheUsageV1 {
    let mut usage = CacheUsageV1::default();
    match kind {
        CachePinKindV1::LogicalLease => usage.logical_pins = 1,
        CachePinKindV1::SourceRetention => usage.source_retentions = 1,
        CachePinKindV1::KernelReference => usage.kernel_references = 1,
        CachePinKindV1::BackingRegistration => usage.backing_registrations = 1,
    }
    usage
}

pub(super) fn add_usage(
    target: &mut CacheUsageV1,
    delta: CacheUsageV1,
) -> Result<(), RecoveryError> {
    target.reservation_bytes = target
        .reservation_bytes
        .checked_add(delta.reservation_bytes)
        .ok_or(RecoveryError::Capacity)?;
    target.residency_bytes = target
        .residency_bytes
        .checked_add(delta.residency_bytes)
        .ok_or(RecoveryError::Capacity)?;
    target.resident_objects = target
        .resident_objects
        .checked_add(delta.resident_objects)
        .ok_or(RecoveryError::Capacity)?;
    target.logical_pins = target
        .logical_pins
        .checked_add(delta.logical_pins)
        .ok_or(RecoveryError::Capacity)?;
    target.source_retentions = target
        .source_retentions
        .checked_add(delta.source_retentions)
        .ok_or(RecoveryError::Capacity)?;
    target.kernel_references = target
        .kernel_references
        .checked_add(delta.kernel_references)
        .ok_or(RecoveryError::Capacity)?;
    target.backing_registrations = target
        .backing_registrations
        .checked_add(delta.backing_registrations)
        .ok_or(RecoveryError::Capacity)?;
    Ok(())
}

pub(super) fn subtract_usage(
    target: &mut CacheUsageV1,
    delta: CacheUsageV1,
) -> Result<(), RecoveryError> {
    target.reservation_bytes = target
        .reservation_bytes
        .checked_sub(delta.reservation_bytes)
        .ok_or(RecoveryError::PayloadMismatch)?;
    target.residency_bytes = target
        .residency_bytes
        .checked_sub(delta.residency_bytes)
        .ok_or(RecoveryError::PayloadMismatch)?;
    target.resident_objects = target
        .resident_objects
        .checked_sub(delta.resident_objects)
        .ok_or(RecoveryError::PayloadMismatch)?;
    target.logical_pins = target
        .logical_pins
        .checked_sub(delta.logical_pins)
        .ok_or(RecoveryError::PayloadMismatch)?;
    target.source_retentions = target
        .source_retentions
        .checked_sub(delta.source_retentions)
        .ok_or(RecoveryError::PayloadMismatch)?;
    target.kernel_references = target
        .kernel_references
        .checked_sub(delta.kernel_references)
        .ok_or(RecoveryError::PayloadMismatch)?;
    target.backing_registrations = target
        .backing_registrations
        .checked_sub(delta.backing_registrations)
        .ok_or(RecoveryError::PayloadMismatch)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct ProjectionAccumulator {
    subjects: u64,
    pub(super) charged_bytes: u64,
    catalog: [u8; 32],
    reservation: [u8; 32],
    pins: [u8; 32],
    progress: [u8; 32],
}

impl ProjectionAccumulator {
    pub(super) fn from_subjects(
        subjects: &BTreeMap<ObjectDigest, CacheAtomicObjectPayloadV1>,
    ) -> Result<Self, RecoveryError> {
        let mut accumulator = Self::default();
        for (subject, payload) in subjects {
            accumulator.replace(*subject, None, payload)?;
        }
        Ok(accumulator)
    }

    pub(super) fn replace(
        &mut self,
        subject: ObjectDigest,
        previous: Option<&CacheAtomicObjectPayloadV1>,
        next: &CacheAtomicObjectPayloadV1,
    ) -> Result<(), RecoveryError> {
        if let Some(previous) = previous {
            self.toggle(subject, previous)?;
            self.charged_bytes = self
                .charged_bytes
                .checked_sub(payload_charged_bytes(previous))
                .ok_or(RecoveryError::ProjectionMismatch)?;
        } else {
            self.subjects = self
                .subjects
                .checked_add(1)
                .ok_or(RecoveryError::Capacity)?;
        }
        self.toggle(subject, next)?;
        self.charged_bytes = self
            .charged_bytes
            .checked_add(payload_charged_bytes(next))
            .ok_or(RecoveryError::Capacity)?;
        Ok(())
    }

    pub(super) fn toggle(
        &mut self,
        subject: ObjectDigest,
        payload: &CacheAtomicObjectPayloadV1,
    ) -> Result<(), RecoveryError> {
        let catalog = payload
            .catalog
            .as_ref()
            .map_or_else(empty_catalog_projection, |entry| entry.digest);
        xor_digest(
            &mut self.catalog,
            projection_leaf(b"aos.sandbox.cache.catalog-leaf.v1\0", subject, catalog),
        );
        xor_digest(
            &mut self.reservation,
            projection_leaf(
                b"aos.sandbox.cache.reservation-leaf.v1\0",
                subject,
                payload.reservation.digest,
            ),
        );
        xor_digest(
            &mut self.pins,
            projection_leaf(
                b"aos.sandbox.cache.pin-leaf.v1\0",
                subject,
                replay_pin_projection(&payload.pins, &payload.released_pins)?,
            ),
        );
        xor_digest(
            &mut self.progress,
            projection_leaf(
                b"aos.sandbox.cache.progress-leaf.v1\0",
                subject,
                subject_progress_projection(payload)?,
            ),
        );
        Ok(())
    }

    pub(super) fn digests(self) -> (ObjectDigest, ObjectDigest, ObjectDigest, ObjectDigest) {
        (
            projection_root(
                b"aos.sandbox.cache.aggregate-catalog.v2\0",
                self.subjects,
                self.catalog,
            ),
            projection_root(
                b"aos.sandbox.cache.aggregate-reservation.v2\0",
                self.subjects,
                self.reservation,
            ),
            projection_root(
                b"aos.sandbox.cache.aggregate-pins.v2\0",
                self.subjects,
                self.pins,
            ),
            projection_root(
                b"aos.sandbox.cache.aggregate-progress.v2\0",
                self.subjects,
                self.progress,
            ),
        )
    }
}

pub(super) fn projection_leaf(
    domain: &[u8],
    subject: ObjectDigest,
    component: ObjectDigest,
) -> ObjectDigest {
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest as _;
    hasher.update(domain);
    hasher.update(subject.as_bytes());
    hasher.update(component.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

pub(super) fn projection_root(domain: &[u8], subjects: u64, accumulator: [u8; 32]) -> ObjectDigest {
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest as _;
    hasher.update(domain);
    hasher.update(subjects.to_be_bytes());
    hasher.update(accumulator);
    ObjectDigest::from_bytes(hasher.finalize().into())
}

pub(super) fn xor_digest(accumulator: &mut [u8; 32], digest: ObjectDigest) {
    for (target, value) in accumulator.iter_mut().zip(digest.as_bytes()) {
        *target ^= value;
    }
}

pub(super) fn subject_progress_projection(
    payload: &CacheAtomicObjectPayloadV1,
) -> Result<ObjectDigest, RecoveryError> {
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest as _;
    hasher.update(b"aos.sandbox.cache.subject-progress.v1\0");
    hasher.update(payload.progress.digest.as_bytes());
    hasher.update(
        payload
            .eviction_plan
            .as_ref()
            .map_or([0; 32], |plan| *plan.digest.as_bytes()),
    );
    hasher.update((payload.eviction_progress.len() as u64).to_be_bytes());
    for progress in &payload.eviction_progress {
        hasher.update(
            digest_bytes(
                b"aos.sandbox.cache.eviction-progress-component.v1\0",
                &encode_eviction_progress(progress, MAXIMUM_COMPONENT_BYTES)?,
            )
            .as_bytes(),
        );
    }
    let scrub = match &payload.scrub {
        Some(scrub) => digest_bytes(
            b"aos.sandbox.cache.scrub-component.v1\0",
            &encode_scrub_record(scrub, payload.plan.partition, MAXIMUM_COMPONENT_BYTES)?,
        ),
        None => ObjectDigest::from_bytes([0; 32]),
    };
    hasher.update(scrub.as_bytes());
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

pub(super) fn aggregate_counts(
    subjects: &BTreeMap<ObjectDigest, CacheAtomicObjectPayloadV1>,
) -> Result<(u64, u64, u64, u64, u64), RecoveryError> {
    let mut catalog_entries = 0_u64;
    let mut reservations = 0_u64;
    let mut pins = 0_u64;
    let mut pending = 0_u64;
    let mut charged = 0_u64;
    for payload in subjects.values() {
        catalog_entries = catalog_entries
            .checked_add(u64::from(
                payload
                    .catalog
                    .as_ref()
                    .is_some_and(|entry| entry.presence != CatalogPresenceV1::Evicted),
            ))
            .ok_or(RecoveryError::Capacity)?;
        reservations = reservations.checked_add(1).ok_or(RecoveryError::Capacity)?;
        pins = pins
            .checked_add(payload.pins.len() as u64)
            .ok_or(RecoveryError::Capacity)?;
        pending = pending
            .checked_add(u64::from(matches!(
                payload.progress.stage,
                AdmissionStageV1::PrivateDestinationCreated
                    | AdmissionStageV1::ContentTransferred
                    | AdmissionStageV1::ContentVerified
                    | AdmissionStageV1::WritersClosed
                    | AdmissionStageV1::SealEnabledAndVerified
                    | AdmissionStageV1::InodeSynced
                    | AdmissionStageV1::CanonicalNamePublished
                    | AdmissionStageV1::ParentSynced
                    | AdmissionStageV1::Uncertain
            )))
            .ok_or(RecoveryError::Capacity)?;
        let pending_evictions = payload
            .eviction_progress
            .iter()
            .filter(|progress| {
                matches!(
                    progress.state,
                    EvictionCandidateStateV1::Selected
                        | EvictionCandidateStateV1::Deleting
                        | EvictionCandidateStateV1::UnlinkAmbiguous
                        | EvictionCandidateStateV1::RemovedAwaitingReclaim
                )
            })
            .count();
        pending = pending
            .checked_add(u64::try_from(pending_evictions).map_err(|_| RecoveryError::Capacity)?)
            .ok_or(RecoveryError::Capacity)?;
        charged = charged
            .checked_add(match payload.reservation.state {
                ReservationStateV1::Reserved | ReservationStateV1::Uncertain => {
                    payload.reservation.reserved_bytes
                }
                ReservationStateV1::Converted => payload.reservation.resident_bytes,
                ReservationStateV1::Released | ReservationStateV1::Evicted => 0,
            })
            .ok_or(RecoveryError::Capacity)?;
    }
    Ok((catalog_entries, reservations, pins, pending, charged))
}

pub(super) fn payload_charged_bytes(payload: &CacheAtomicObjectPayloadV1) -> u64 {
    match payload.reservation.state {
        ReservationStateV1::Reserved | ReservationStateV1::Uncertain => {
            payload.reservation.reserved_bytes
        }
        ReservationStateV1::Converted => payload.reservation.resident_bytes,
        ReservationStateV1::Released | ReservationStateV1::Evicted => 0,
    }
}

pub(super) fn validate_watermark_gate(
    global: &CacheGlobalRecoveryStateV1,
    charged_bytes: u64,
) -> Result<(), RecoveryError> {
    if charged_bytes <= global.node_quota.high_water_bytes {
        return if global.watermarks.is_empty() {
            Ok(())
        } else {
            Err(RecoveryError::PayloadMismatch)
        };
    }
    let [requirement] = global.watermarks.as_slice() else {
        return Err(RecoveryError::PayloadMismatch);
    };
    let required_remaining = charged_bytes
        .checked_sub(global.node_quota.low_water_bytes)
        .ok_or(RecoveryError::PayloadMismatch)?;
    if requirement
        .required_bytes
        .checked_sub(requirement.credited_bytes)
        != Some(required_remaining)
    {
        return Err(RecoveryError::PayloadMismatch);
    }
    Ok(())
}
