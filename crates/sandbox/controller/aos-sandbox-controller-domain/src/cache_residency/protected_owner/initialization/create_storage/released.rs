//! Retains Cache Released on the same original initialized HOLD writer.
//!
//! The original clock and all five writers remain held through Root6. This
//! owner appends revision two only after genuine committed U, retains every
//! returned native result and completes the original final five audit slots.

use super::*;
use aos_sandbox_model::ResourceDimension as D;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    KEY_BYTES,
    continuation::ContinuationNativeReceiptDataV1,
    outcome::{ReleasedBodyDataV1, RELEASED_BODY_BYTES_V1, RELEASED_RECORD_BYTES_V1},
};
use crate::controller_resource_reservation::CacheReleaseReceivingLoanV1;

#[derive(Default)]
pub(crate) struct CacheReleasedOriginalsV1 {
    entered: bool,
    entry: Option<Result<(), CacheHeldErrorV1>>,
    shape: Option<Result<CacheReleasedShapeV1, CacheHeldErrorV1>>,
    fixed: Option<Result<(), ResourceReservationErrorV1>>,
    before: Option<audit::CacheHeldBookendsV1>,
    body: Option<Result<[u8; RELEASED_BODY_BYTES_V1], CacheHeldErrorV1>>,
    record: Option<Result<[u8; RELEASED_RECORD_BYTES_V1], CacheHeldErrorV1>>,
    head: Option<[u8; HEAD_BYTES]>,
    transaction: Option<Result<Arc<JournalTransaction>, CacheHeldErrorV1>>,
    crossing: [Option<Result<(), CacheHeldErrorV1>>; 2],
    crossing_posts: [Option<audit::CacheHeldBookendsV1>; 2],
    append_geometry: Option<Result<ResourceVector, JournalError>>,
    append_funding: Option<Result<(), ResourceReservationErrorV1>>,
    append: Option<Result<CommitResult, JournalError>>,
    readback: Option<Result<HistoryPairReadbackV1<RELEASED_RECORD_BYTES_V1>, CacheHeldErrorV1>>,
    after_hold_position: crate::journal::CreateStorageWriterPositionOriginalV1,
    after_hold: Option<Result<CacheHeldWriterShapeV1, CacheHeldErrorV1>>,
    after: Option<audit::CacheHeldBookendsV1>,
    current_after: Option<Result<(), ResourceReservationErrorV1>>,
    primary: Option<Result<(), CacheHeldErrorV1>>,
    final_audits: Option<Result<(), CacheHeldClosedV1>>,
    audit_returned: Option<Result<(), CacheHeldClosedV1>>,
    audit_clock: crate::policy_compiler::RetainedKernelPairedClockAttemptV1,
    audit_clock_result: Option<Result<aos_sandbox_model::RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
    audit_cutoff: Option<Result<(), ResourceReservationErrorV1>>,
    complete: bool,
    selected_control: Option<CacheReleasedCurrentnessSiteV1>,
    failed_audit: Option<audit::CacheHeldAuditV1>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct CacheReleasedShapeV1 {
    identity: CacheHeldIdentityDataV1,
    extents: [crate::journal::ProtectedJournalPreopenReplayExtentV1; 5],
    semantic_peak: ResourceVector,
    complete: ResourceVector,
}

impl CacheReleasedShapeV1 {
    pub(crate) fn identity_v1(&self) -> CacheHeldIdentityDataV1 { self.identity }
    pub(crate) fn complete_receiving_demand_v1(&self) -> ResourceVector { self.complete }
    pub(crate) fn semantic_peak_v1(&self) -> ResourceVector { self.semantic_peak }
}

impl CacheReleasedOriginalsV1 {
    pub(crate) fn started(&self) -> bool { self.entered }

    pub(crate) fn append_funding_failure_is_selected_v1(&self) -> bool {
        matches!(self.append_geometry, Some(Ok(_))) && matches!(self.append_funding, Some(Err(_)))
    }


    pub(crate) fn identity_v1(&self) -> Result<CacheHeldIdentityDataV1, CacheHeldClosedV1> {
        self.receipt_v1()?;
        self.shape.as_ref().and_then(|shape| shape.as_ref().ok()).map(|shape| shape.identity)
            .ok_or(CacheHeldClosedV1)
    }

    pub(super) fn after_hold_shape_v1(&self) -> Option<&CacheHeldWriterShapeV1> {
        if !self.complete || self.failure().is_some() { return None; }
        self.after_hold.as_ref().and_then(|shape| shape.as_ref().ok())
    }


    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.failure_before_audits_v1()
            .or_else(|| self.failed_audit.as_ref().and_then(audit::CacheHeldAuditV1::failure))
            .or_else(|| error(&self.audit_returned)).or_else(|| self.audit_clock.failure())
            .or_else(|| error(&self.audit_clock_result)).or_else(|| error(&self.audit_cutoff))
            .or_else(|| error(&self.final_audits))
    }

    fn failure_before_audits_v1(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.entry).or_else(|| error(&self.shape)).or_else(|| error(&self.fixed))
            .or_else(|| self.before.as_ref().and_then(audit::CacheHeldBookendsV1::failure))
            .or_else(|| error(&self.body)).or_else(|| error(&self.record))
            .or_else(|| error(&self.transaction))
            .or_else(|| error(&self.append_geometry)).or_else(|| error(&self.append_funding))
            .or_else(|| error(&self.crossing[0]))
            .or_else(|| self.crossing_posts[0].as_ref().and_then(audit::CacheHeldBookendsV1::failure))
            .or_else(|| error(&self.crossing[1]))
            .or_else(|| self.crossing_posts[1].as_ref().and_then(audit::CacheHeldBookendsV1::failure))
            .or_else(|| error(&self.append)).or_else(|| error(&self.readback))
            .or_else(|| self.after_hold_position.failure()).or_else(|| error(&self.after_hold))
            .or_else(|| error(&self.primary))
            .or_else(|| self.after.as_ref().and_then(audit::CacheHeldBookendsV1::failure))
            .or_else(|| error(&self.current_after))
    }

    pub(crate) fn selected_control_v1(&self) -> Option<CacheReleasedCurrentnessSiteV1> {
        self.selected_control
    }

    pub(crate) fn receipt_v1(&self) -> Result<ContinuationNativeReceiptDataV1<'_>, CacheHeldClosedV1> {
        if !self.complete || self.failure().is_some() { return Err(CacheHeldClosedV1); }
        let observed = self.readback.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CacheHeldClosedV1)?;
        let shape = self.after_hold.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CacheHeldClosedV1)?;
        Ok(ContinuationNativeReceiptDataV1 { record: &observed.record,
            latest_head: observed.head, names: shape.coordinates.names,
            after_next: observed.next, after_end: shape.coordinates.end })
    }
}

pub(crate) fn release_append_bytes_v1() -> Result<u64, CacheHeldErrorV1> {
    aos_sandbox_journal::geometry::encoded_transaction_append_bytes([
        aos_sandbox_journal::geometry::RecordShape { key_bytes: KEY_BYTES, value_bytes: Some(RELEASED_RECORD_BYTES_V1) },
        aos_sandbox_journal::geometry::RecordShape { key_bytes: KEY_BYTES, value_bytes: Some(HEAD_BYTES) },
    ].into_iter()).map_err(|_| CacheHeldErrorV1::Order)
}

pub(crate) fn release_receiving_demand_v1(
    extents: &[crate::journal::ProtectedJournalPreopenReplayExtentV1; 5],
) -> Result<ResourceVector, CacheHeldErrorV1> {
    let append = release_append_bytes_v1()?;
    let mut after = *extents;
    after[1] = crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
        extents[1].limits, extents[1].native_bytes.checked_add(append).ok_or(CacheHeldErrorV1::Order)?,
    )?;
    let bytes = std::mem::size_of::<CacheReleasedOriginalsV1>().checked_mul(2)
        .and_then(|bytes| bytes.checked_add(std::mem::align_of::<CacheReleasedOriginalsV1>()))
        .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<CacheReleaseReceivingLoanV1<'_>>()))
        .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<CacheReleasedAppendLoanV1<'_, '_, '_>>()))
        .ok_or(CacheHeldErrorV1::Order)?;
    let clock_bytes = crate::policy_compiler::RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
        .ok_or(CacheHeldErrorV1::Order)?;
    let clock_files = crate::policy_compiler::RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1;
    let framing = usize::try_from(append).ok()
        .and_then(|bytes| bytes.checked_add(KEY_BYTES * 2 + RELEASED_RECORD_BYTES_V1 + HEAD_BYTES))
        .and_then(|bytes| bytes.checked_add(7 + KEY_BYTES + RELEASED_RECORD_BYTES_V1))
        .and_then(|bytes| bytes.checked_add(aos_sandbox_journal::framing::COMMIT_PAYLOAD_BYTES))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<(JournalTransaction, [crate::journal::JournalRecord; 2], [Vec<u8>; 4])>()))
        .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<(Vec<u8>, [usize; 6])>()))
        .ok_or(CacheHeldErrorV1::Order)?;
    // Four resident outer/crossing sets and one active terminal reader's set.
    // Positive readers actually drop before the next original audit ordinal.
    receiving::fixed_readonly_demand(bytes, 5 * 5)?
        .checked_add(current_receiving::create_storage_cache_current_dynamic_receiving_demand_v1(&after)?)?
        .checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(framing.checked_add(clock_bytes).ok_or(CacheHeldErrorV1::Order)?)
                .map_err(|_| CacheHeldErrorV1::Order)?)
            .with(D::OpenFiles, u64::try_from(clock_files).map_err(|_| CacheHeldErrorV1::Order)?)
            .with(D::MetadataEntries, 1)
            .with(D::StorageBytes, append).with(D::OutputBytes, append)
            .with(D::PublicationStagingBytes, append)).map_err(Into::into)
}

/// Borrows only the actual held Cache and admitted same-U release original.
pub(crate) struct CacheReleasedAppendLoanV1<'crossing, 'original, 'cache> {
    cache: &'crossing mut OriginalCreateStorageCacheLoanV1<'cache>,
    released: &'crossing mut CacheReleasedOriginalsV1,
    receiving: &'crossing mut CacheReleaseReceivingLoanV1<'original>,
}

impl OriginalCreateStorageCacheLoanV1<'_> {
    pub(crate) fn release_receiving_shape_v1(&self) -> Result<CacheReleasedShapeV1, CacheHeldErrorV1> {
        self.require_pre_root_cut_v1().map_err(|_| CacheHeldErrorV1::Order)?;
        let current = self.current_proof_extents_v1()?;
        let extents = *current.extents_v1();
        let mut after = extents;
        let append = release_append_bytes_v1()?;
        after[1] = crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
            extents[1].limits, extents[1].native_bytes.checked_add(append).ok_or(CacheHeldErrorV1::Order)?,
        )?;
        let mut semantic_peak = ResourceVector::ZERO;
        for extent in &after {
            semantic_peak = semantic_peak.componentwise_max(extent.dominant_semantic_receiving_demand_v1()?);
        }
        Ok(CacheReleasedShapeV1 { identity: self.identity, extents: after, semantic_peak,
            complete: release_receiving_demand_v1(&extents)? })
    }

    pub(crate) fn release_original_held_once(&mut self,
        released: &mut CacheReleasedOriginalsV1,
        receiving: &mut CacheReleaseReceivingLoanV1<'_>,
    ) -> Result<(), CacheHeldClosedV1> {
        if released.entered { return Err(CacheHeldClosedV1); }
        released.entered = true;
        released.entry = Some((|| {
            self.require_pre_root_cut_v1().map_err(|_| CacheHeldErrorV1::Order)?;
            if self.progress.audit_next != 10 || self.progress.active_audit.is_some()
                || self.progress.root.is_some() || self.progress.finished {
                return Err(CacheHeldErrorV1::Order);
            }
            Ok(())
        })());
        released.shape = Some(self.release_receiving_shape_v1());
        released.fixed = Some(match released.shape.as_ref().and_then(|result| result.as_ref().ok()) {
            Some(shape) => receiving.require_cache_release_shape_v1(shape),
            None => Err(ResourceReservationErrorV1::Conflict),
        });
        released.before = Some(audit::observe_bookends(&mut self.originals, self.progress, None));
        released.primary = Some(self.produce_released_inner(released, receiving));
        // The unchanged originals remain available even when the body or U
        // admission has failed. A positive append selects only its real shape.
        let after = released.after_hold.as_ref().and_then(|result| result.as_ref().ok());
        released.after = Some(audit::observe_bookends_with_hold_v1(
            &mut self.originals, self.progress, None, after,
        ));
        released.current_after = Some(receiving.observe_cache_release_currentness_once(
            self, CacheReleasedCurrentnessSiteV1::After,
        ));
        if matches!(released.primary, Some(Ok(())))
            && released.after.as_ref().is_some_and(|posts| posts.failure().is_none())
            && matches!(released.current_after, Some(Err(_))) {
            released.selected_control = Some(CacheReleasedCurrentnessSiteV1::After);
        }
        if matches!(released.primary, Some(Ok(())))
            && matches!(released.current_after, Some(Ok(())))
            && released.after.as_ref().is_some_and(|posts| posts.failure().is_none()) {
            released.final_audits = Some(self.audit_original_released_once(released, receiving));
        }
        released.complete = matches!(released.primary, Some(Ok(())))
            && matches!(released.final_audits, Some(Ok(())))
            && self.progress.audit_next == 15 && released.failure().is_none();
        if released.complete { Ok(()) } else { Err(CacheHeldClosedV1) }
    }

    fn produce_released_inner(&mut self,
        released: &mut CacheReleasedOriginalsV1,
        receiving: &mut CacheReleaseReceivingLoanV1<'_>,
    ) -> Result<(), CacheHeldErrorV1> {
        if !matches!(released.entry, Some(Ok(()))) || !matches!(released.fixed, Some(Ok(())))
            || released.before.as_ref().is_none_or(|posts| posts.failure().is_some()) {
            return Err(CacheHeldErrorV1::Order);
        }
        if let Err(cause) = receiving.observe_cache_release_currentness_once(self, CacheReleasedCurrentnessSiteV1::Before) {
            released.selected_control = Some(CacheReleasedCurrentnessSiteV1::Before);
            return Err(cause.into());
        }
        let lane = receiving.lane_v1()?;
        let held = self.held_receipt_data_v1().map_err(|_| CacheHeldErrorV1::Order)?;
        let held = RecordEnvelopeV1::decode(held.record, KeyV1::new(lane, OwnerV1::Cache, 1)?,
            PhaseV1::new(OwnerV1::Cache, 1)?)?;
        let predecessor = held.checksum();
        let correlation = held.coordinates().correlation;
        released.body = Some(receiving.released_body_v1(predecessor)
            .map_err(CacheHeldErrorV1::from).and_then(|body| body.encode(OwnerV1::Cache).map_err(Into::into)));
        let body = released.body.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CacheHeldErrorV1::Order)?;
        released.record = Some((|| {
            let mut record = [0; RELEASED_RECORD_BYTES_V1];
            let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
                key: KeyV1::new(lane, OwnerV1::Cache, 2)?, phase: PhaseV1::new(OwnerV1::Cache, 2)?,
                predecessor, correlation,
            }, body, &mut record)?;
            released.head = Some(LatestHeadV1::new(2, checksum)?.encode());
            Ok(record)
        })());
        let record = released.record.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CacheHeldErrorV1::Order)?;
        let head = released.head.as_ref().ok_or(CacheHeldErrorV1::Order)?;
        released.transaction = Some(prepare_history_pair_v1(KeyV1::new(lane, OwnerV1::Cache, 2)?,
            PhaseV1::new(OwnerV1::Cache, 2)?, record, head).map(Arc::new).map_err(Into::into));
        let transaction = released.transaction.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CacheHeldErrorV1::Order)?;
        released.append_geometry = Some(self.originals.hold.as_deref().ok_or(CacheHeldErrorV1::Order)?
            .cache_held_append_semantic_demand_v1(transaction));
        released.append_funding = Some((|| {
            let semantic = released.append_geometry.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            receiving.admit_cache_append_semantic_v1(semantic)
        })());
        if !matches!(released.append_funding, Some(Ok(()))) { return Err(CacheHeldErrorV1::Order); }
        let hold = self.originals.hold.take().ok_or(CacheHeldErrorV1::Order)?;
        // This is the same actual transaction allocation, not a new Native
        // request or a copied source of mutation authority.
        let transaction = Arc::clone(transaction);
        let mut crossing = CacheReleasedAppendLoanV1 { cache: self, released, receiving };
        let append = hold.commit_create_storage_cache_released_v1(&transaction, &mut crossing);
        self.originals.hold = Some(hold);
        released.append = Some(append);
        let append = released.append.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CacheHeldErrorV1::Order)?;
        let before = self.progress.after_hold.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CacheHeldErrorV1::Order)?;
        let record = released.record.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CacheHeldErrorV1::Order)?;
        let head = released.head.as_ref().ok_or(CacheHeldErrorV1::Order)?;
        let hold = self.originals.hold.as_deref().ok_or(CacheHeldErrorV1::Order)?;
        released.readback = Some(readback_history_pair_v1(hold, &transaction, record, head,
            before.coordinates.next, append).map_err(Into::into));
        released.after_hold = Some(hold.capture_cache_held_shape_v1(
            &mut released.after_hold_position, InitializerJournal::Hold, self.originals.uid,
        ).map_err(Into::into));
        let after = released.after_hold.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CacheHeldErrorV1::Order)?;
        let observed = released.readback.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CacheHeldErrorV1::Order)?;
        let forecast = released.shape.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CacheHeldErrorV1::Order)?;
        if after.coordinates.names != before.coordinates.names || after.coordinates.next != observed.next
            || after.coordinates.end != append.durable_bytes || after.extent != forecast.extents[1] {
            return Err(CacheHeldErrorV1::Order);
        }
        Ok(())
    }
}

/// Names the new purpose's actual four independently retained control passes.
#[derive(Clone, Copy)]
pub(crate) enum CacheReleasedCurrentnessSiteV1 { Before, Transition, FinalCrossing, After }

impl CacheReleasedAppendLoanV1<'_, '_, '_> {
    pub(crate) fn require_transition(&mut self, target: &Journal, transaction: &JournalTransaction)
        -> Result<(), JournalError> {
        self.crossing_once(target, Some(transaction), 0, CacheReleasedCurrentnessSiteV1::Transition)
    }

    pub(crate) fn final_crossing(&mut self, target: &Journal) -> Result<(), JournalError> {
        self.crossing_once(target, None, 1, CacheReleasedCurrentnessSiteV1::FinalCrossing)
    }

    fn crossing_once(&mut self, target: &Journal, transaction: Option<&JournalTransaction>, index: usize,
        site: CacheReleasedCurrentnessSiteV1,
    ) -> Result<(), JournalError> {
        if self.released.crossing[index].is_some() { return Err(JournalError::ProtectedBoundary); }
        self.released.crossing[index] = Some((|| {
            self.receiving.require_cache_named_preparation(self.cache.identity)?;
            let expected = self.cache.progress.after_hold.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(CacheHeldErrorV1::Order)?;
            expected.require(target)?;
            let lane = self.receiving.lane_v1()?;
            let held = self.cache.held_receipt_data_v1().map_err(|_| CacheHeldErrorV1::Order)?;
            let key = KeyV1::new(lane, OwnerV1::Cache, 1)?;
            let latest = KeyV1::new(lane, OwnerV1::Cache, 0)?;
            let mut rows = 0_usize;
            for (stored, value) in target.records(crate::RecordNamespace::CreateStorageHistory) {
                rows += 1;
                if stored == key.encode() && value == held.record { continue; }
                if stored == latest.encode() && value == held.latest_head { continue; }
                return Err(CacheHeldErrorV1::Order);
            }
            if rows != 2 { return Err(CacheHeldErrorV1::Order); }
            if let Some(transaction) = transaction {
                let prepared = self.released.transaction.as_ref().and_then(|result| result.as_ref().ok())
                    .ok_or(CacheHeldErrorV1::Order)?;
                if prepared.as_ref() != transaction { return Err(CacheHeldErrorV1::Order); }
            }
            Ok(())
        })());
        self.released.crossing_posts[index] = Some(audit::observe_bookends(
            &mut self.cache.originals, self.cache.progress, Some(target),
        ));
        let current = self.receiving.observe_cache_release_currentness_once(self.cache, site);
        if matches!(self.released.crossing[index], Some(Ok(())))
            && self.released.crossing_posts[index].as_ref().is_some_and(|posts| posts.failure().is_none())
            && current.is_err() && self.released.selected_control.is_none() {
            self.released.selected_control = Some(site);
        }
        if !matches!(self.released.crossing[index], Some(Ok(())))
            || self.released.crossing_posts[index].as_ref().is_none_or(|posts| posts.failure().is_some())
            || current.is_err() {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

impl OriginalCreateStorageCacheLoanV1<'_> {
    fn audit_original_released_once(&mut self, released: &mut CacheReleasedOriginalsV1,
        receiving: &mut CacheReleaseReceivingLoanV1<'_>,
    ) -> Result<(), CacheHeldClosedV1> {
        while self.progress.audit_next < 15 {
            let index = self.progress.audit_next;
            if index < 10 || self.progress.active_audit.is_some() { return Err(CacheHeldClosedV1); }
            let writer = index % 5;
            let shape = self.progress.shape.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CacheHeldClosedV1)?;
            let held = self.progress.after_hold.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CacheHeldClosedV1)?;
            let after = released.after_hold.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CacheHeldClosedV1)?;
            let expected = if writer == 1 { after } else { &shape.writers[writer] };
            let held_transaction = self.progress.transaction.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(CacheHeldClosedV1)?;
            let release_transaction = released.transaction.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(CacheHeldClosedV1)?;
            let positions = [shape.writers[1].coordinates, held.coordinates, after.coordinates];
            self.progress.active_audit = Some(audit::CacheHeldAuditV1::new());
            let native_base = receiving.cache_native_base_v1().map_err(|_| CacheHeldClosedV1)?;
            let active = self.progress.active_audit.as_mut().ok_or(CacheHeldClosedV1)?;
            released.audit_returned = Some(active.replay_released_once(&self.originals,
                native::CacheHeldReadonlyPayerV1::Release(receiving), self.identity, native_base,
                expected, writer, held_transaction, release_transaction, positions));
            let posts = audit::observe_bookends_with_hold_v1(
                &mut self.originals, self.progress, None, Some(after),
            );
            self.progress.active_audit.as_mut().ok_or(CacheHeldClosedV1)?.posts = Some(posts);
            released.audit_clock_result = Some(released.audit_clock.observe_once(None));
            released.audit_cutoff = Some(match &released.audit_clock_result {
                Some(Ok(clock)) => receiving.require_current_clock_v1(*clock),
                _ => Err(ResourceReservationErrorV1::Conflict),
            });
            let active = self.progress.active_audit.as_ref().ok_or(CacheHeldClosedV1)?;
            if !matches!(released.audit_returned, Some(Ok(()))) || active.failure().is_some()
                || !matches!(active.equality, Some(Ok(())))
                || writer == 1 && !active.released_suffix_is_complete_v1()
                || released.audit_clock.failure().is_some()
                || !matches!(released.audit_cutoff, Some(Ok(()))) {
                released.failed_audit = self.progress.active_audit.take();
                return Err(CacheHeldClosedV1);
            }
            let report = active.report.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(CacheHeldClosedV1)?;
            self.progress.audits[index] = Some(audit::CacheHeldAuditDataV1 { coordinates: expected.coordinates, report });
            // Native reader, all actual posts and cutoff comparison are now
            // positive. Their physical disposal precedes the next ordinal.
            drop(self.progress.active_audit.take());
            drop(std::mem::take(&mut released.audit_clock));
            released.audit_clock_result = None;
            released.audit_cutoff = None;
            released.audit_returned = None;
            self.progress.audit_next += 1;
        }
        Ok(())
    }


}
