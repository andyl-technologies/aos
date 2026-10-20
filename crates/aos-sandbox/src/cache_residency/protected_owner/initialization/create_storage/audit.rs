//! Retains one actual readonly audit until every independent post succeeds.
//!
//! The next audit reuses a peak only after the same reader is actually dropped.
//! Failed openings, whole Native results, suffix progress, payment errors and
//! all independently attempted name/physical/clock posts remain resident.

use super::*;
use crate::journal::create_storage_history::{
    HistoryPairNativeSuffixProgressV1, HistoryPairNativeSuffixV1,
};

struct WriterPostV1 {
    position: crate::journal::CreateStorageWriterPositionOriginalV1,
    comparison: Option<Result<(), CacheHeldErrorV1>>,
}

impl WriterPostV1 {
    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.position.failure().or_else(|| error(&self.comparison))
    }
}

pub(super) struct CacheHeldBookendsV1 {
    writers: [WriterPostV1; 5],
    physical_original: CachePhysicalReadbackOriginalsV1,
    physical: Result<(), CacheHeldErrorV1>,
    clock: Result<(), CacheHeldErrorV1>,
    selection: Option<Result<(), CacheHeldErrorV1>>,
}

impl CacheHeldBookendsV1 {
    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.writers.iter().find_map(WriterPostV1::failure)
            .or_else(|| self.physical_original.failure())
            .or_else(|| self.physical.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.clock.as_ref().err().map(|cause| cause as _))
            .or_else(|| error(&self.selection))
    }
}

/// Keeps compact comparison DATA after concrete positive reader disposal.
pub(super) struct CacheHeldAuditDataV1 {
    pub(super) coordinates: CacheJournalDataV1,
    pub(super) report: crate::journal::RecoveryReport,
}

pub(super) struct CacheHeldAuditV1 {
    pub(super) opening: Option<ReadOnlyJournalOpenOriginalsV1>,
    pub(super) prepared: Option<Result<(), CacheHeldErrorV1>>,
    pub(super) opening_failed_at_preparation: bool,
    pub(super) suffix: HistoryPairNativeSuffixProgressV1,
    released_suffix: HistoryPairNativeSuffixProgressV1,
    released_active: usize,
    released_recipe_error: Option<crate::journal::create_storage_history::HistoryPairSuffixErrorV1>,
    pub(super) suffix_prepared: Option<Result<(), CacheHeldErrorV1>>,
    pub(super) geometry: Option<Result<ResourceVector, JournalError>>,
    pub(super) admission: Option<Result<(), ResourceReservationErrorV1>>,
    pub(super) report: Option<Result<crate::journal::RecoveryReport, CacheHeldErrorV1>>,
    pub(super) equality: Option<Result<(), CacheHeldErrorV1>>,
    pub(super) posts: Option<CacheHeldBookendsV1>,
}

enum CacheAuditSuffixDataV1<'data> {
    None,
    Held(Option<&'data Arc<JournalTransaction>>, CacheJournalDataV1),
    Released(&'data Arc<JournalTransaction>, &'data Arc<JournalTransaction>, [CacheJournalDataV1; 3]),
}

impl CacheHeldAuditV1 {
    pub(super) fn new() -> Self {
        Self {
            opening: Some(ReadOnlyJournalOpenOriginalsV1::new()),
            prepared: None,
            opening_failed_at_preparation: false,
            suffix: HistoryPairNativeSuffixProgressV1::new(),
            released_suffix: HistoryPairNativeSuffixProgressV1::new(),
            released_active: 0,
            released_recipe_error: None,
            suffix_prepared: None,
            geometry: None,
            admission: None,
            report: None,
            equality: None,
            posts: None,
        }
    }

    fn equality_failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause = self.equality.as_ref()?.as_ref().err()?;
        let index = match cause {
            CacheHeldErrorV1::Journal(JournalError::ReadOnlyNameReceivingFailure(index))
            | CacheHeldErrorV1::Protected(ProtectedDomainJournalErrorV1::Journal(
                JournalError::ReadOnlyNameReceivingFailure(index))) => Some(*index),
            _ => None,
        };
        if let Some(index) = index {
            // Resolve only this exact archived stage. A later generic opening
            // post or another name failure cannot replace its native cause.
            if let Some(native) = self.opening.as_ref()
                .and_then(|opening| opening.named_receiving_failure(index))
            {
                return Some(native);
            }
        }
        Some(cause)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        // Geometry/payment/suffix causes arise inside the parser before its
        // coarse refusal; project those actual typed causes ahead of that row.
        let original_preparation = self.prepared.as_ref().and_then(|value| value.as_ref().err())
            .filter(|cause| !self.opening_failed_at_preparation && !matches!(cause, CacheHeldErrorV1::Order))
            .map(|cause| cause as &(dyn Error + 'static));
        original_preparation
            .or_else(|| error(&self.geometry))
            .or_else(|| error(&self.admission))
            .or_else(|| self.suffix.failure().map(|cause| cause as _))
            .or_else(|| self.released_suffix.failure().map(|cause| cause as _))
            .or_else(|| self.released_recipe_error.as_ref().map(|cause| cause as _))
            .or_else(|| error(&self.report))
            .or_else(|| self.equality_failure())
            .or_else(|| self.opening.as_ref().and_then(ReadOnlyJournalOpenOriginalsV1::failure))
            .or_else(|| error(&self.prepared))
            .or_else(|| error(&self.suffix_prepared))
            .or_else(|| self.posts.as_ref().and_then(CacheHeldBookendsV1::failure))
    }
    // Initial fifteen audits and the later current-proof purpose enter this
    // SAME reader/suffix/semantic/equality engine. Each actual payer variant
    // remains borrowed until all parser frontiers finish.
    pub(super) fn replay_once(
        &mut self,
        originals: &CacheHeldOriginalsV1<'_>,
        original: super::native::CacheHeldReadonlyPayerV1<'_, '_>,
        identity: CacheHeldIdentityDataV1,
        complete_base: ResourceVector,
        expected: &CacheHeldWriterShapeV1,
        writer: usize,
        suffix: Option<(Option<&Arc<JournalTransaction>>, CacheJournalDataV1)>,
    ) -> Result<(), CacheHeldClosedV1> {
        let purpose = match suffix {
            Some((transaction, before)) => CacheAuditSuffixDataV1::Held(transaction, before),
            None => CacheAuditSuffixDataV1::None,
        };
        self.replay_purpose_once(originals, original, identity, complete_base, expected, writer, purpose)
    }

    pub(super) fn replay_released_once(
        &mut self,
        originals: &CacheHeldOriginalsV1<'_>,
        original: super::native::CacheHeldReadonlyPayerV1<'_, '_>,
        identity: CacheHeldIdentityDataV1,
        complete_base: ResourceVector,
        expected: &CacheHeldWriterShapeV1,
        writer: usize,
        held: &Arc<JournalTransaction>,
        released: &Arc<JournalTransaction>,
        positions: [CacheJournalDataV1; 3],
    ) -> Result<(), CacheHeldClosedV1> {
        let suffix = if writer == 1 {
            CacheAuditSuffixDataV1::Released(held, released, positions)
        } else { CacheAuditSuffixDataV1::None };
        self.replay_purpose_once(originals, original, identity, complete_base, expected, writer, suffix)
    }

    pub(super) fn released_suffix_is_complete_v1(&self) -> bool {
        self.suffix.is_complete() && self.released_suffix.is_complete()
    }

    fn replay_purpose_once(
        &mut self,
        originals: &CacheHeldOriginalsV1<'_>,
        original: super::native::CacheHeldReadonlyPayerV1<'_, '_>,
        identity: CacheHeldIdentityDataV1,
        complete_base: ResourceVector,
        expected: &CacheHeldWriterShapeV1,
        writer: usize,
        suffix: CacheAuditSuffixDataV1<'_>,
    ) -> Result<(), CacheHeldClosedV1> {
        let opening = self.opening.as_mut().ok_or(CacheHeldClosedV1)?;
        let (suffix, released_suffix) = match suffix {
            CacheAuditSuffixDataV1::Held(transaction, before) => {
                let suffix = match transaction {
                    Some(transaction) => {
                        match HistoryPairNativeSuffixV1::new(transaction, &mut self.suffix,
                            before.next, before.end, expected.coordinates.next, expected.coordinates.end)
                        {
                            Ok(suffix) => {
                                self.suffix_prepared = Some(Ok(()));
                                Some(suffix)
                            }
                            Err(_) => {
                                // The original typed recipe cause stays in
                                // the independently owned suffix progress.
                                self.suffix_prepared = Some(Err(CacheHeldErrorV1::Order));
                                None
                            }
                        }
                    }
                    None => {
                        self.suffix_prepared = Some(Err(CacheHeldErrorV1::Order));
                        None
                    }
                };
                (suffix, None)
            }
            CacheAuditSuffixDataV1::Released(held, released, positions) => {
                let positions = positions.map(|position| (position.next, position.end));
                let prepared = crate::journal::create_storage_history::ControllerHistoryNativeSuffixV1::<2>::
                    new_cache_released_v1([held, released], [&mut self.suffix, &mut self.released_suffix],
                        &mut self.released_active, positions);
                match prepared {
                    Ok(suffix) => { self.suffix_prepared = Some(Ok(())); (None, Some(suffix)) }
                    Err(cause) => {
                        self.released_recipe_error = Some(cause);
                        self.suffix_prepared = Some(Err(CacheHeldErrorV1::Order));
                        (None, None)
                    }
                }
            }
            CacheAuditSuffixDataV1::None => (None, None),
        };
        if !matches!(self.suffix_prepared, Some(Err(_))) {
            let mut context = CacheHeldReadonlyContextV1 {
                original,
                identity,
                complete_base,
                captured_end: expected.extent.native_bytes,
                suffix,
                released_suffix,
                geometry: &mut self.geometry,
                admission: &mut self.admission,
            };
            self.prepared = Some(prepare_reader(originals, expected, writer, opening, &mut context));
            self.opening_failed_at_preparation = opening.failure().is_some();
            if matches!(self.prepared, Some(Ok(()))) {
                opening.replay_captured_cache_once(&mut context);
            }
            drop(context);
        }
        self.report = opening.cache_held_report_data_v1().map(|report| {
            if report.truncated_bytes != 0 {
                Err(JournalError::ProtectedBoundary.into())
            } else {
                Ok(report)
            }
        });
        self.equality = opening.readback_mut().map(|readback| {
            compare_reader(originals, expected, writer, readback)
        });
        if opening.cache_held_attempted_v1() { opening.recheck_named_once(); }
        Ok(())
    }

}

impl OriginalCreateStorageCacheLoanV1<'_> {
    pub(super) fn observe_posts_once(&mut self, index: usize) {
        if index >= self.progress.posts.len() || self.progress.posts[index].is_some() {
            self.progress.refuse();
            return;
        }
        let posts = observe_bookends(&mut self.originals, self.progress, None);
        let failed = posts.failure().is_some();
        self.progress.posts[index] = Some(posts);
        self.progress.mark(failed, Failure::Post(index));
    }

    pub(super) fn audit_once(
        &mut self,
        original: &mut CreateStorageOriginalLoanV1<'_>,
        index: usize,
    ) -> Result<(), CacheHeldClosedV1> {
        if self.progress.first.is_some() || self.progress.audit_next != index
            || index >= 15 || self.progress.active_audit.is_some()
        {
            self.progress.refuse();
            return Err(CacheHeldClosedV1);
        }
        self.progress.active_audit = Some(CacheHeldAuditV1::new());
        let shape = self.progress.shape.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(CacheHeldClosedV1)?;
        let writer = index % 5;
        let after = index >= 5 && writer == 1;
        let expected = if after {
            self.progress.after_hold.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(CacheHeldClosedV1)?
        } else {
            &shape.writers[writer]
        };
        let suffix = after.then(|| (
            self.progress.transaction.as_ref().and_then(|value| value.as_ref().ok()),
            shape.writers[1].coordinates,
        ));
        self.progress.active_audit.as_mut().ok_or(CacheHeldClosedV1)?.replay_once(
            &self.originals,
            super::native::CacheHeldReadonlyPayerV1::Initial(original),
            self.identity, shape.complete_base(), expected, writer, suffix,
        )?;
        // No earlier opening/parser result can suppress these originals' posts.
        let posts = observe_bookends(&mut self.originals, self.progress, None);
        self.progress.active_audit.as_mut().ok_or(CacheHeldClosedV1)?.posts = Some(posts);
        if self.progress.active_audit.as_ref().is_some_and(|audit| audit.failure().is_some()) {
            self.progress.mark(true, Failure::Audit);
            return Err(CacheHeldClosedV1);
        }
        let active = self.progress.active_audit.as_ref().ok_or(CacheHeldClosedV1)?;
        let report = active.report.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(CacheHeldClosedV1)?;
        if !matches!(active.equality, Some(Ok(()))) || (after && !active.suffix.is_complete()) {
            self.progress.refuse();
            return Err(CacheHeldClosedV1);
        }
        self.progress.audits[index] = Some(CacheHeldAuditDataV1 { coordinates: expected.coordinates, report });
        // Actual positive disposal precedes peak reuse. Negative/incomplete
        // owners never reach this take and remain in their original field.
        drop(self.progress.active_audit.take());
        self.progress.audit_next += 1;
        Ok(())
    }
}

fn prepare_reader(
    originals: &CacheHeldOriginalsV1<'_>,
    expected: &CacheHeldWriterShapeV1,
    writer: usize,
    opening: &mut ReadOnlyJournalOpenOriginalsV1,
    receiving: &mut CacheHeldReadonlyContextV1<'_, '_, '_>,
) -> Result<(), CacheHeldErrorV1> {
    if writer == 0 {
        return originals.source.prepare_create_storage_readback_v1(expected, opening, receiving).map_err(Into::into);
    }
    let name = writer_name(writer)?;
    opening.prepare_captured_cache_once(Path::new(PROTECTED_CACHE_ROOT), name, expected.limits(),
        originals.uid, expected.coordinates.names.directory(), receiving);
    if opening.failure().is_some() { return Err(CacheHeldErrorV1::Order); }
    if opening.captured_extent() != Some(&expected.extent) {
        return Err(JournalError::StaleAuthoritySnapshot.into());
    }
    Ok(())
}

fn compare_reader(
    originals: &CacheHeldOriginalsV1<'_>,
    expected: &CacheHeldWriterShapeV1,
    writer: usize,
    readback: &mut crate::journal::ReadOnlyProtectedJournal,
) -> Result<(), CacheHeldErrorV1> {
    match writer {
        0 => originals.source.require_create_storage_readback_v1(expected, readback)?,
        1 => originals.hold.as_deref().ok_or(CacheHeldErrorV1::Order)?
            .require_cache_held_readback_v1(expected, readback)?,
        2 => originals.state.require_cache_held_readback_v1(expected, readback)?,
        3 => originals.authority.check_named_location(|journal| {
            journal.require_cache_held_readback_v1(expected, readback)
        })?,
        4 => {
            let clock = originals.clock_owner.state.lock().map_err(|_| CacheHeldErrorV1::Order)?;
            clock.journal.as_ref().ok_or(CacheHeldErrorV1::Order)?
                .require_cache_held_readback_v1(expected, readback)?;
        }
        _ => return Err(CacheHeldErrorV1::Order),
    }
    Ok(())
}

fn writer_name(index: usize) -> Result<&'static str, CacheHeldErrorV1> {
    match index {
        1 => Ok(CACHE_POLICY_HOLD_JOURNAL),
        2 => Ok(CACHE_STATE_JOURNAL),
        3 => Ok(CACHE_AUTHORITY_JOURNAL),
        4 => Ok(CACHE_CLOCK_JOURNAL),
        _ => Err(CacheHeldErrorV1::Order),
    }
}

pub(super) fn observe_bookends(
    originals: &mut CacheHeldOriginalsV1<'_>,
    progress: &CacheHeldProgressV1,
    crossing_hold: Option<&Journal>,
) -> CacheHeldBookendsV1 {
    observe_bookends_with_hold_v1(originals, progress, crossing_hold, None)
}

pub(super) fn observe_bookends_with_hold_v1(
    originals: &mut CacheHeldOriginalsV1<'_>,
    progress: &CacheHeldProgressV1,
    crossing_hold: Option<&Journal>,
    released_hold: Option<&CacheHeldWriterShapeV1>,
) -> CacheHeldBookendsV1 {
    let shape = progress.shape.as_ref().and_then(|value| value.as_ref().ok());
    let mut source_post = WriterPostV1 { position: Default::default(), comparison: None };
    source_post.comparison = Some(originals.source.observe_create_storage_position_v1(
        &mut source_post.position, shape.map(|shape| &shape.writers[0]),
    ).map_err(Into::into));
    let hold = crossing_hold.or(originals.hold.as_deref());
    let hold_expected = released_hold.or_else(|| progress.after_hold.as_ref().and_then(|value| value.as_ref().ok()))
        .or_else(|| shape.map(|shape| &shape.writers[1]));
    let hold_post = writer_post(hold, InitializerJournal::Hold, originals.uid, hold_expected);
    let state_post = writer_post(Some(originals.state), InitializerJournal::State, originals.uid,
        shape.map(|shape| &shape.writers[2]));
    let mut authority_post = WriterPostV1 { position: Default::default(), comparison: None };
    let authority_result = originals.authority.check_named_location(|journal| {
        authority_post.position.capture_cache_once(journal, InitializerJournal::Authority, originals.uid);
        authority_post.position.position()?;
        if let Some(shape) = shape { shape.writers[3].require_observed(journal, &authority_post.position)?; }
        Ok(())
    });
    authority_post.comparison = Some(authority_result.map_err(Into::into));
    let clock_post = match originals.clock_owner.state.lock() {
        Ok(clock) => writer_post(clock.journal.as_ref(), InitializerJournal::Clock, originals.uid,
            shape.map(|shape| &shape.writers[4])),
        Err(_) => WriterPostV1 { position: Default::default(), comparison: Some(Err(CacheHeldErrorV1::Order)) },
    };
    let mut physical_original = CachePhysicalReadbackOriginalsV1::default();
    let physical = originals.physical.capture_create_storage_physical_once(
        &mut physical_original, originals.physical_identity,
    ).map(|_| ()).map_err(Into::into);
    let clock = originals.clock.as_ref().map_or_else(|| Err(CacheHeldErrorV1::Order), |clock| {
        clock.require_create_storage_hold_v1().map_err(Into::into)
    });
    let selection = progress.selection.as_ref().and_then(|value| value.as_ref().ok()).map(|selection| {
        let clock = originals.clock.as_ref().ok_or(CacheHeldErrorV1::Order)?;
        originals.authority.recheck_create_storage_selection_v1(originals.state, clock, selection)
            .map_err(Into::into)
    });
    CacheHeldBookendsV1 {
        writers: [source_post, hold_post, state_post, authority_post, clock_post],
        physical_original, physical, clock, selection,
    }
}

fn writer_post(
    journal: Option<&Journal>,
    role: InitializerJournal,
    uid: u32,
    expected: Option<&CacheHeldWriterShapeV1>,
) -> WriterPostV1 {
    let mut post = WriterPostV1 { position: Default::default(), comparison: None };
    post.comparison = Some((|| {
        let journal = journal.ok_or(CacheHeldErrorV1::Order)?;
        post.position.capture_cache_once(journal, role, uid);
        post.position.position()?;
        if let Some(expected) = expected { expected.require_observed(journal, &post.position)?; }
        Ok(())
    })());
    post
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_preparation_projection_does_not_mask_actual_native_opening_cause() {
        let mut audit = CacheHeldAuditV1::new();
        let opening = audit.opening.as_mut().unwrap();
        // Negative Native opening mechanics only: no J payment or successful
        // Cache ownership is fabricated by this deliberately absent root.
        opening.prepare_captured_once(
            Path::new("/rfc21-cache-held-absent-native-fixture"), "state.journal",
            JournalLimits::default(), 0, (1, 2),
        );
        enum OriginalCause {
            Open(*const rustix::io::Errno),
            Boundary(*const JournalError),
        }

        impl OriginalCause {
            fn assert_same(&self, observed: &(dyn std::error::Error + 'static)) {
                match self {
                    Self::Open(original) => assert!(std::ptr::eq(
                        observed.downcast_ref::<rustix::io::Errno>().unwrap(), *original,
                    )),
                    Self::Boundary(original) => assert!(std::ptr::eq(
                        observed.downcast_ref::<JournalError>().unwrap(), *original,
                    )),
                }
            }
        }

        // The original rooted recipe can refuse the actual root's ancestry
        // before the absent-child open. Keep that exact protection refusal,
        // or the actual open errno when the root is admissible.
        let cause = opening.failure().unwrap();
        let native = if let Some(cause) = cause.downcast_ref::<rustix::io::Errno>() {
            OriginalCause::Open(cause as *const _)
        } else {
            let cause = cause.downcast_ref::<JournalError>().unwrap();
            assert!(matches!(cause, JournalError::ProtectedBoundary));
            OriginalCause::Boundary(cause as *const _)
        };
        audit.opening_failed_at_preparation = opening.failure().is_some();
        // The Source helper returns this coarse projection after parking the
        // complete actual opening cause in the same destination.
        audit.prepared = Some(Err(CacheHeldErrorV1::Journal(JournalError::ProtectedBoundary)));

        native.assert_same(audit.failure().unwrap());
        audit.opening.as_mut().unwrap().recheck_named_once();
        native.assert_same(audit.failure().unwrap());
        assert!(audit.opening.is_some());
    }

    #[test]
    fn reached_geometry_cause_and_partial_reader_survive_later_debt() {
        let mut audit = CacheHeldAuditV1::new();
        audit.geometry = Some(Err(JournalError::LimitExceeded("reached Cache row")));
        let original = audit.geometry.as_ref().unwrap().as_ref().unwrap_err()
            as *const JournalError;

        // An unentered reader closes on this invalid post; it must not replace
        // the earlier typed geometry cause or dispose its owning destination.
        audit.opening.as_mut().unwrap().recheck_named_once();
        audit.admission = Some(Err(ResourceReservationErrorV1::Conflict));

        let observed = audit.failure().unwrap().downcast_ref::<JournalError>().unwrap();
        assert!(std::ptr::eq(observed, original));
        assert!(audit.opening.is_some());
        assert!(audit.opening.as_ref().unwrap().failure().is_some());
        assert!(matches!(audit.admission, Some(Err(ResourceReservationErrorV1::Conflict))));
    }
}
