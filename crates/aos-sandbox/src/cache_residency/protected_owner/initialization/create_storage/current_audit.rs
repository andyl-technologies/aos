//! Retains a distinct five-reader Cache current-proof audit under the same loan.
//!
//! Each reader uses the existing captured native/suffix/physical engine. The
//! new purpose owns its own results and must be paid before entry. Failed
//! primary and independently owed posts remain resident; only a complete
//! positive reader is physically dropped before its peak can be reused.

use super::*;
use super::audit::{CacheHeldAuditDataV1, CacheHeldAuditV1, CacheHeldBookendsV1};
use crate::controller_resource_reservation::CacheCurrentAuditReceivingLoanV1;

#[derive(Clone, Copy)]
enum CurrentFailure {
    Entry,
    Before,
    Reader,
    After,
}

/// Carries the new live purpose's actual native fixed/prefix BASE as DATA.
pub(crate) struct CacheCurrentAuditShapeV1 {
    identity: CacheHeldIdentityDataV1,
    base: ResourceVector,
    semantic_peak: ResourceVector,
}

impl CacheCurrentAuditShapeV1 {
    pub(crate) fn original_identity_v1(&self) -> CacheHeldIdentityDataV1 { self.identity }

    pub(crate) fn dominant_receiving_demand_v1(&self) -> ResourceVector { self.base }

    pub(crate) fn semantic_peak_v1(&self) -> ResourceVector { self.semantic_peak }
}

/// Owns the new current-purpose roster without consuming a terminal audit.
#[derive(Default)]
pub(crate) struct CacheCurrentAuditOriginalsV1 {
    armed: bool,
    entered: bool,
    entry: Option<Result<(), CacheHeldErrorV1>>,
    before: Option<CacheHeldBookendsV1>,
    active: Option<CacheHeldAuditV1>,
    completed: [Option<CacheHeldAuditDataV1>; 5],
    next: usize,
    after: Option<CacheHeldBookendsV1>,
    first: Option<CurrentFailure>,
    readers_complete: bool,
    complete: bool,
    post_clock: crate::policy_compiler::RetainedKernelPairedClockAttemptV1,
    post_clock_result: Option<Result<aos_sandbox_core::RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
    post_cutoff: Option<Result<(), ResourceReservationErrorV1>>,
    completed_clocks: [Option<aos_sandbox_core::RawPairedClockSample>; 5],
    reader_returned: Option<Result<(), CacheHeldClosedV1>>,
}

impl CacheCurrentAuditOriginalsV1 {
    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            CurrentFailure::Entry => error(&self.entry),
            CurrentFailure::Before => self.before.as_ref().and_then(CacheHeldBookendsV1::failure),
            CurrentFailure::Reader => self.active.as_ref().and_then(CacheHeldAuditV1::failure)
                .or_else(|| error(&self.reader_returned))
                .or_else(|| self.post_clock.failure())
                .or_else(|| error(&self.post_clock_result)).or_else(|| error(&self.post_cutoff)),
            CurrentFailure::After => self.after.as_ref().and_then(CacheHeldBookendsV1::failure),
        }
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.complete && self.first.is_none() && self.active.is_none()
            && self.next == 5 && self.completed.iter().all(Option::is_some)
    }
}

impl OriginalCreateStorageCacheLoanV1<'_> {
    /// Derives the new audit BASE from the actual completed pre-Root originals.
    ///
    /// # Errors
    /// Refuses an incomplete original cut or checked fixed/prefix arithmetic.
    /// No native reopen, allocation, parser or new receiving begins here.
    pub(crate) fn current_proof_audit_shape_v1(&self)
        -> Result<CacheCurrentAuditShapeV1, CacheHeldErrorV1>
    {
        let extents = self.current_proof_extents_v1()?;
        let semantic_peak = extents.semantic_peak_v1()?;
        Ok(CacheCurrentAuditShapeV1 {
            identity: self.identity,
            base: current_receiving::current_cache_fixed_receiving_demand_v1()?
                .checked_add(extents.dynamic_receiving_demand_v1()?)?,
            semantic_peak,
        })
    }

    pub(crate) fn current_proof_extents_v1(&self)
        -> Result<current_receiving::CreateStorageCacheCurrentExtentsDataV1, CacheHeldErrorV1>
    {
        self.require_pre_root_cut_v1().map_err(|_| CacheHeldErrorV1::Order)?;
        let shape = self.progress.shape.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CacheHeldErrorV1::Order)?;
        let after = self.progress.after_hold.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CacheHeldErrorV1::Order)?;
        Ok(current_receiving::CreateStorageCacheCurrentExtentsDataV1::from_captured_extents_v1([
            shape.writers[0].extent, after.extent, shape.writers[2].extent,
            shape.writers[3].extent, shape.writers[4].extent,
        ]))
    }

    /// Arms the exact current-audit native post after genuine fixed admission.
    ///
    /// # Errors
    /// Retains wrong original, incomplete pre-Root cut, prior active parser or
    /// an already armed current purpose. This pure method performs no IO.
    pub(crate) fn arm_current_proof_audit_once(
        &self,
        current: &mut CacheCurrentAuditOriginalsV1,
        receiving: &mut CacheCurrentAuditReceivingLoanV1<'_>,
    ) -> Result<(), CacheHeldClosedV1> {
        if current.armed || current.entry.is_some() {
            return Err(CacheHeldClosedV1);
        }
        current.entry = Some((|| {
            self.require_pre_root_cut_v1().map_err(|_| CacheHeldErrorV1::Order)?;
            receiving.require_cache_named_preparation(self.identity)?;
            if self.progress.active_audit.is_some() || self.progress.audit_next != 10 {
                return Err(CacheHeldErrorV1::Order);
            }
            Ok(())
        })());
        if matches!(current.entry, Some(Ok(()))) {
            current.armed = true;
            Ok(())
        } else {
            current.first = Some(CurrentFailure::Entry);
            Err(CacheHeldClosedV1)
        }
    }

    /// Audits the five exact post-Held originals for the new current purpose.
    ///
    /// # Errors
    /// Retains first entry, native/parser/semantic/equality or independent post
    /// failure. The concrete genuine J loan pays/verifies each reached bound.
    pub(crate) fn audit_current_proof_once(
        &mut self,
        current: &mut CacheCurrentAuditOriginalsV1,
        receiving: &mut CacheCurrentAuditReceivingLoanV1<'_>,
    ) -> Result<(), CacheHeldClosedV1> {
        if current.entered {
            return Err(CacheHeldClosedV1);
        }
        current.entered = true;
        if !current.armed || !matches!(current.entry, Some(Ok(()))) {
            return Err(CacheHeldClosedV1);
        }
        current.before = Some(super::audit::observe_bookends(
            &mut self.originals, self.progress, None,
        ));
        if current.before.as_ref().is_some_and(|posts| posts.failure().is_some()) {
            current.first = Some(CurrentFailure::Before);
        }

        while current.first.is_none() && current.next < 5 {
            let writer = current.next;
            let shape = self.progress.shape.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(CacheHeldClosedV1)?;
            let expected = if writer == 1 {
                self.progress.after_hold.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or(CacheHeldClosedV1)?
            } else { &shape.writers[writer] };
            let suffix = (writer == 1).then(|| (
                self.progress.transaction.as_ref().and_then(|value| value.as_ref().ok()),
                shape.writers[1].coordinates,
            ));
            current.active = Some(CacheHeldAuditV1::new());
            let active = current.active.as_mut().ok_or(CacheHeldClosedV1)?;
            let native_base = receiving.cache_native_base_v1();
            current.reader_returned = Some(active.replay_once(
                &self.originals,
                super::native::CacheHeldReadonlyPayerV1::Current(receiving),
                self.identity, native_base, expected, writer, suffix,
            ));
            // Independent same-original posts run even after native/geometry
            // payment failure. They do not reopen an earlier admission.
            current.active.as_mut().ok_or(CacheHeldClosedV1)?.posts = Some(
                super::audit::observe_bookends(&mut self.originals, self.progress, None),
            );
            let active = current.active.as_ref().ok_or(CacheHeldClosedV1)?;
            // Time is freshly observed after this complete reader and all
            // its independent native posts, before its original scratch drops.
            current.post_clock_result = Some(current.post_clock.observe_once(None));
            current.post_cutoff = Some(match &current.post_clock_result {
                Some(Ok(clock)) => receiving.require_current_clock_v1(*clock),
                _ => Err(ResourceReservationErrorV1::Conflict),
            });
            if !matches!(current.reader_returned, Some(Ok(()))) || active.failure().is_some()
                || current.post_clock.failure().is_some()
                || !matches!(current.post_cutoff, Some(Ok(())))
                || !matches!(active.equality, Some(Ok(())))
                || writer == 1 && !active.suffix.is_complete()
            {
                current.first = Some(CurrentFailure::Reader);
                break;
            }
            let report = active.report.as_ref().and_then(|value| value.as_ref().ok()).copied()
                .ok_or(CacheHeldClosedV1)?;
            current.completed[writer] = Some(CacheHeldAuditDataV1 {
                coordinates: expected.coordinates, report,
            });
            // The same reader, parser scratch and complete posts are actually
            // gone before another reader may reuse this native peak.
            drop(current.active.take());
            // This exact positive native clock primitive has already retired
            // its own boot files. The enclosing complete reader needs no later
            // borrower of this fresh sample; only its compact verdict remains.
            current.completed_clocks[writer] = current.post_clock_result.as_ref()
                .and_then(|result| result.as_ref().ok()).copied();
            current.post_clock = Default::default();
            current.post_clock_result = None;
            current.post_cutoff = None;
            current.reader_returned = None;
            current.next += 1;
        }

        current.readers_complete = current.first.is_none() && current.next == 5;
        if current.readers_complete { Ok(()) } else { Err(CacheHeldClosedV1) }
    }

    /// Runs the current purpose's independently owed Cache post after its flight.
    ///
    /// # Errors
    /// Refuses a missing entry, repeated post or any earlier/final observation.
    /// Entered native work remains observable even when the genuine J ledger
    /// has already closed; this method obtains no new admission or peak.
    pub(crate) fn finish_current_proof_audit_once(
        &mut self,
        current: &mut CacheCurrentAuditOriginalsV1,
    ) -> Result<(), CacheHeldClosedV1> {
        if !current.armed || current.after.is_some() {
            return Err(CacheHeldClosedV1);
        }
        current.after = Some(super::audit::observe_bookends(
            &mut self.originals, self.progress, None,
        ));
        if current.after.as_ref().is_some_and(|posts| posts.failure().is_some()) {
            current.first.get_or_insert(CurrentFailure::After);
        }
        current.complete = current.readers_complete && current.first.is_none() && current.next == 5;
        if current.is_complete() { Ok(()) } else { Err(CacheHeldClosedV1) }
    }
}
