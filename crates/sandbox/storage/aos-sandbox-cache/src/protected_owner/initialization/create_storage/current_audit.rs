//! Retains each real Current reader across the upper clock and cutoff check.
//!
//! The same private five-writer audit owns native replay, equality and all
//! independent native posts. The upper owner retains its actual kernel-clock
//! attempt and Root-turn cutoff error; only its positive path retires a reader
//! before another may reuse the native peak. These observations grant no phase.

use super::*;
use super::audit::{CacheHeldAuditDataV1, CacheHeldAuditV1, CacheHeldBookendsV1};

#[derive(Clone, Copy)]
enum CurrentFailure {
    Entry,
    Before,
    Reader,
    After,
}

/// Describes the exact actual Current Cache shape without admitting work.
pub struct CacheCurrentAuditShapeV1 {
    identity: CacheHeldIdentityDataV1,
    base: ResourceVector,
    semantic_peak: ResourceVector,
}

impl CacheCurrentAuditShapeV1 {
    /// Returns equality DATA from the actual borrowed Cache owners.
    pub fn original_identity_v1(&self) -> CacheHeldIdentityDataV1 { self.identity }

    /// Returns the complete native plus actual upper fixed receiving bound.
    pub fn dominant_receiving_demand_v1(&self) -> ResourceVector { self.base }

    /// Returns the independently derived private five-prefix semantic peak.
    pub fn semantic_peak_v1(&self) -> ResourceVector { self.semantic_peak }
}

/// Keeps the same Current native owners until their actual posts complete.
///
/// Its public observations are comparison and diagnostic DATA. Only the live
/// initialized Cache loan can arm or enter it. Upper clock/cutoff destinations
/// remain upper; their failure never disposes this retained native reader.
#[derive(Default)]
pub struct CacheCurrentAuditOriginalsV1 {
    armed: bool,
    entered: bool,
    entry: Option<Result<(), CacheHeldErrorV1>>,
    shape: Option<Result<CacheCurrentAuditShapeV1, CacheHeldErrorV1>>,
    before: Option<CacheHeldBookendsV1>,
    active: Option<CacheHeldAuditV1>,
    completed: [Option<CacheHeldAuditDataV1>; 5],
    next: usize,
    after: Option<CacheHeldBookendsV1>,
    first: Option<CurrentFailure>,
    readers_complete: bool,
    complete: bool,
    reader_returned: Option<Result<(), CacheHeldClosedV1>>,
}

impl CacheCurrentAuditOriginalsV1 {
    /// Borrows the original native failure without another observation.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first {
            Some(CurrentFailure::Entry) => error(&self.shape)
                .or_else(|| error(&self.entry)),
            Some(CurrentFailure::Before) => self.before.as_ref()
                .and_then(CacheHeldBookendsV1::failure),
            Some(CurrentFailure::Reader) | None => self.active.as_ref()
                .and_then(CacheHeldAuditV1::failure)
                .or_else(|| error(&self.reader_returned)),
            Some(CurrentFailure::After) => self.after.as_ref()
                .and_then(CacheHeldBookendsV1::failure),
        }
    }

    /// Returns the reached complete Cache geometry without granting admission.
    pub fn reached_cache_complete_v1(&self) -> Option<ResourceVector> {
        self.active.as_ref()?.geometry.as_ref()?.as_ref().ok().copied()
    }

    /// Reports the actual reached semantic admission without another debit.
    pub fn reached_semantic_admission_succeeded_v1(&self) -> bool {
        self.active.as_ref().is_some_and(|active| matches!(active.admission, Some(Ok(()))))
    }

    /// Reports an actual U debit refusal after positive reached geometry.
    pub fn storage_use_semantic_funding_failed_v1(&self) -> bool {
        self.active.as_ref().is_some_and(|active| {
            matches!(active.geometry, Some(Ok(_)))
                && matches!(active.admission, Some(Err(ControllerCacheAuditFundingErrorV1::StorageUse(_))))
        })
    }

    /// Reports completion of this native roster, without an upper phase grant.
    pub fn is_complete(&self) -> bool {
        self.complete && self.first.is_none() && self.active.is_none()
            && self.next == 5 && self.completed.iter().all(Option::is_some)
    }

    /// Returns the ordinal of the next original Current reader.
    pub fn next_reader_index_v1(&self) -> usize { self.next }

    /// Reports whether the retained reader has reached its upper clock slot.
    pub fn reader_requires_clock_post_v1(&self) -> bool {
        self.active.is_some() && self.reader_returned.is_some()
    }

    /// Reports whether all five original reader owners were positively retired.
    pub fn readers_complete_v1(&self) -> bool { self.readers_complete }

    /// Prices the finite Current shape and suspended-entry control planes.
    ///
    /// This excludes the upper's actual kernel sampler and cutoff diagnostics;
    /// their exact compiled quote is added by the sole upper caller. The same
    /// B worker owns these inline progress reservoirs, while this quote covers
    /// actual construction/forwarding controls before the Current admission.
    pub fn receiving_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;

        // New entry closure captures actual self, the stored shape and the
        // genuine mutable lender. The old suffix closure is source-conserved
        // and receives no duplicate charge here.
        let arm_entry = size_of::<(
            &OriginalCreateStorageCacheLoanV1<'_>,
            &Option<Result<CacheCurrentAuditShapeV1, CacheHeldErrorV1>>,
            &mut ControllerCacheAuditFundingLoanV1<'_, '_>,
        )>().checked_mul(2)?
            .checked_add(size_of::<Result<(), CacheHeldErrorV1>>().checked_mul(2)?)?;
        size_of::<current_receiving::CreateStorageCacheCurrentExtentsDataV1>().checked_mul(2)?
            .checked_add(arm_entry)?
            .checked_add(crate::journal::readonly_receiving::full_prefix_peak_control_bytes_v1()?)?
            .checked_add(size_of::<Option<ResourceVector>>().checked_mul(4)?)?
            .checked_add(size_of::<(&[crate::journal::ProtectedJournalPreopenReplayExtentV1; 5], Option<ResourceVector>)>())?
            .checked_add(size_of::<Result<ResourceVector, CacheHeldErrorV1>>().checked_mul(2)?)?
            .checked_add(size_of::<Result<ResourceVector, JournalError>>().checked_mul(2)?)?
            .checked_add(size_of::<ResourceVector>().checked_mul(8)?)?
            .checked_add(size_of::<Result<ResourceVector, JournalError>>().checked_mul(4)?)?
            .checked_add(size_of::<(usize, usize, &crate::journal::ProtectedJournalPreopenReplayExtentV1)>())?
            .checked_add(size_of::<Result<CacheCurrentAuditShapeV1, CacheHeldErrorV1>>().checked_mul(2)?)?
            .checked_add(size_of::<Result<(), CacheHeldClosedV1>>().checked_mul(10)?)?
            .checked_add(size_of::<ResourceVector>().checked_mul(8)?)?
            .checked_add(size_of::<Result<ControllerCacheAuditFundingLoanV1<'_, '_>, ControllerCacheAuditFundingErrorV1>>().checked_mul(4)?)?
            .checked_add(size_of::<Result<ResourceVector, CacheHeldErrorV1>>().checked_mul(2)?)?
            .checked_add(size_of::<(&ControllerSourceOriginalRefV1, &CacheCurrentAuditShapeV1)>().checked_mul(2)?)?
            .checked_add(size_of::<(
                &OriginalCreateStorageCacheLoanV1<'_>,
                &mut CacheCurrentAuditOriginalsV1,
                &mut ControllerCacheAuditFundingLoanV1<'_, '_>,
            )>().checked_mul(5)?)
    }
}

impl OriginalCreateStorageCacheLoanV1<'_> {
    /// Captures passive native shape with the actual upper fixed quote added.
    ///
    /// The sole upper caller supplies its compiled kernel/forwarding quote,
    /// never a paid receipt. Native prefix and prepaid semantic bounds are
    /// independently derived here and the same full shape must match the real
    /// financial facade before named opening or replay can enter.
    ///
    /// # Errors
    /// Refuses an incomplete original cut or checked receiving arithmetic.
    pub fn current_proof_audit_shape_v1(
        &self,
        upper_fixed: Option<ResourceVector>,
        semantic_supplement: Option<ResourceVector>,
    ) -> Result<CacheCurrentAuditShapeV1, CacheHeldErrorV1> {
        let extents = self.current_proof_extents_v1()?;
        let semantic_peak = crate::journal::readonly_receiving::full_prefix_semantic_peak_with_supplement_v1(
            extents.extents_v1(), semantic_supplement,
        )?;
        let native_fixed = current_cache_fixed_receiving_demand_v1()?;
        let upper_fixed = upper_fixed.ok_or(JournalError::DeferredUpperFixedQuote)?;
        let fixed = native_fixed.checked_add(upper_fixed)?;
        Ok(CacheCurrentAuditShapeV1 {
            identity: self.identity,
            base: fixed.checked_add(extents.dynamic_receiving_with_semantic_supplement_v1(
                semantic_supplement,
            )?)?,
            semantic_peak,
        })
    }

    /// Borrows the actual post-Held five-prefix bounds as comparison DATA.
    ///
    /// # Errors
    /// Refuses an incomplete pre-Root original or absent positive held shape.
    pub fn current_proof_extents_v1(
        &self,
    ) -> Result<current_receiving::CreateStorageCacheCurrentExtentsDataV1, CacheHeldErrorV1> {
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

    /// Arms native Current only after the actual full admission succeeds.
    ///
    /// # Errors
    /// Retains reentry, a foreign financial purpose/original, mismatched actual
    /// shape or an incomplete pre-Root cut. This performs no native IO.
    pub fn arm_current_proof_audit_once(
        &self,
        current: &mut CacheCurrentAuditOriginalsV1,
        funding: &mut ControllerCacheAuditFundingLoanV1<'_, '_>,
        upper_fixed: Option<ResourceVector>,
        semantic_supplement: Option<ResourceVector>,
    ) -> Result<(), CacheHeldClosedV1> {
        if current.armed || current.entry.is_some() { return Err(CacheHeldClosedV1); }
        current.shape = Some(self.current_proof_audit_shape_v1(upper_fixed, semantic_supplement));
        current.entry = Some((|| {
            self.require_pre_root_cut_v1().map_err(|_| CacheHeldErrorV1::Order)?;
            let shape = current.shape.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(CacheHeldErrorV1::Order)?;
            self.originals.construction.require_audit_funding_originals_v1(funding)?;
            funding.require_cache_shape_v1(self.identity, shape.base, shape.semantic_peak)?;
            funding.require_current_original_v1(self.identity)?;
            if self.progress.active_audit.is_some() || self.progress.audit_next != 10 {
                return Err(CacheHeldErrorV1::Order);
            }
            Ok(())
        })());
        if matches!(current.entry, Some(Ok(()))) { current.armed = true; Ok(()) }
        else { current.first = Some(CurrentFailure::Entry); Err(CacheHeldClosedV1) }
    }

    /// Runs the original independent native before checks once.
    ///
    /// # Errors
    /// Retains reentry, an unarmed entry or any original native before failure.
    pub fn begin_current_proof_audit_once(
        &mut self,
        current: &mut CacheCurrentAuditOriginalsV1,
    ) -> Result<(), CacheHeldClosedV1> {
        if current.entered { return Err(CacheHeldClosedV1); }
        current.entered = true;
        if !current.armed || !matches!(current.entry, Some(Ok(()))) {
            return Err(CacheHeldClosedV1);
        }
        current.before = Some(audit::observe_bookends(&mut self.originals, self.progress, None));
        if current.before.as_ref().is_some_and(|posts| posts.failure().is_some()) {
            current.first = Some(CurrentFailure::Before);
            return Err(CacheHeldClosedV1);
        }
        Ok(())
    }

    /// Captures one complete native reader and its independently owed posts.
    ///
    /// A negative reader still returns to its upper clock/cutoff slot. The
    /// caller must attempt that original slot before selecting failure or
    /// positively retiring the retained reader; no new peak is reused here.
    ///
    /// # Errors
    /// Refuses wrong entry/order or absent original shape before reader entry.
    pub fn capture_current_reader_once_v1(
        &mut self,
        current: &mut CacheCurrentAuditOriginalsV1,
        funding: &mut ControllerCacheAuditFundingLoanV1<'_, '_>,
    ) -> Result<(), CacheHeldClosedV1> {
        if !current.entered || current.first.is_some() || current.next >= 5
            || current.active.is_some() || current.reader_returned.is_some()
        { return Err(CacheHeldClosedV1); }
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
        let priced = current.shape.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(CacheHeldClosedV1)?;
        current.active = Some(CacheHeldAuditV1::new());
        current.reader_returned = Some(current.active.as_mut().ok_or(CacheHeldClosedV1)?.replay_once(
            &self.originals, funding, self.identity, priced.base, priced.semantic_peak,
            expected, writer, suffix,
        ));
        current.active.as_mut().ok_or(CacheHeldClosedV1)?.posts = Some(
            audit::observe_bookends(&mut self.originals, self.progress, None),
        );
        Ok(())
    }

    /// Retains a reader after its actual upper clock/cutoff refuses.
    ///
    /// The owning upper error remains upper. This refusal cannot positively
    /// dispose a reader or advance its ordinal, admit work or grant a phase.
    pub fn retain_current_reader_after_upper_refusal_v1(
        &self,
        current: &mut CacheCurrentAuditOriginalsV1,
    ) {
        current.first.get_or_insert(CurrentFailure::Reader);
    }

    /// Positively retires a reader after the upper's actual clock/cutoff check.
    ///
    /// # Errors
    /// Retains native replay/equality/suffix/post failure or a wrong ordinal.
    pub fn retire_current_reader_after_upper_clock_v1(
        &self,
        current: &mut CacheCurrentAuditOriginalsV1,
    ) -> Result<(), CacheHeldClosedV1> {
        let writer = current.next;
        let active = current.active.as_ref().ok_or(CacheHeldClosedV1)?;
        if current.first.is_some() || writer >= 5
            || !matches!(current.reader_returned, Some(Ok(())))
            || active.failure().is_some() || !matches!(active.equality, Some(Ok(())))
            || writer == 1 && !active.suffix.is_complete()
        {
            current.first.get_or_insert(CurrentFailure::Reader);
            return Err(CacheHeldClosedV1);
        }
        let shape = self.progress.shape.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(CacheHeldClosedV1)?;
        let expected = if writer == 1 {
            self.progress.after_hold.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(CacheHeldClosedV1)?
        } else { &shape.writers[writer] };
        let report = active.report.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(CacheHeldClosedV1)?;
        current.completed[writer] = Some(CacheHeldAuditDataV1 { coordinates: expected.coordinates, report });
        drop(current.active.take());
        current.reader_returned = None;
        current.next += 1;
        current.readers_complete = current.next == 5;
        Ok(())
    }

    /// Runs the original independently owed native after checks once.
    ///
    /// # Errors
    /// Retains missing entry, reentry or any earlier/native after failure.
    pub fn finish_current_proof_audit_once(
        &mut self,
        current: &mut CacheCurrentAuditOriginalsV1,
    ) -> Result<(), CacheHeldClosedV1> {
        if !current.armed || current.after.is_some() { return Err(CacheHeldClosedV1); }
        current.after = Some(audit::observe_bookends(&mut self.originals, self.progress, None));
        if current.after.as_ref().is_some_and(|posts| posts.failure().is_some()) {
            current.first.get_or_insert(CurrentFailure::After);
        }
        current.complete = current.readers_complete && current.first.is_none() && current.next == 5;
        if current.is_complete() { Ok(()) } else { Err(CacheHeldClosedV1) }
    }
}

impl<'cache> OriginalCreateStorageCacheLoanV1<'cache> {
    /// Binds this private Current shape to the same already-admitted J original.
    ///
    /// # Errors
    /// Preserves actual Controller/Source/profile/RootExchange bound refusal.
    pub fn bind_current_j_audit_funding_v1<'funding, 'profile>(
        &self,
        original: aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateContinuationFundingLoanV1<'funding, 'profile>,
        source: &'funding ControllerSourceOriginalRefV1,
        shape: &CacheCurrentAuditShapeV1,
        non_cache: ResourceVector,
        property_traffic: ResourceVector,
    ) -> Result<ControllerCacheAuditFundingLoanV1<'funding, 'profile>, ControllerCacheAuditFundingErrorV1>
    where 'cache: 'funding,
    {
        if shape.identity != self.identity {
            return Err(aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchErrorV1::Conflict.into());
        }
        let construction: &'cache super::super::baseline::CacheConstructionOriginalsV1 = self.originals.construction;
        construction.bind_current_j_audit_funding_v1(original, source, self.identity,
            non_cache, shape.base, property_traffic, shape.semantic_peak)
    }

    /// Debits and binds the distinct Current purpose on the same actual U once.
    ///
    /// # Errors
    /// Preserves actual Controller/Source/profile, arithmetic or U debit refusal.
    pub fn bind_current_u_audit_funding_v1<'funding, 'profile>(
        &self,
        original: aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateStorageUseFundingLoanV1<'funding, 'profile>,
        source: &'funding ControllerSourceOriginalRefV1,
        shape: &CacheCurrentAuditShapeV1,
        non_cache: ResourceVector,
    ) -> Result<ControllerCacheAuditFundingLoanV1<'funding, 'profile>, ControllerCacheAuditFundingErrorV1>
    where 'cache: 'funding,
    {
        if shape.identity != self.identity {
            return Err(aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchErrorV1::Conflict.into());
        }
        let construction: &'cache super::super::baseline::CacheConstructionOriginalsV1 = self.originals.construction;
        construction.bind_current_u_audit_funding_v1(original, source, self.identity,
            non_cache, shape.base, shape.semantic_peak)
    }
}

/// Prices the same private Current fixed native backing before actual admission.
///
/// The upper owner separately adds its real kernel-clock/forwarding controls;
/// this DATA quote creates no payer, initialized owner or phase permission.
///
/// # Errors
/// Rejects checked compiled-layout/native-path receiving arithmetic overflow.
#[doc(hidden)]
pub fn current_cache_fixed_receiving_demand_v1() -> Result<ResourceVector, CacheHeldErrorV1> {
    use aos_sandbox_model::ResourceDimension as D;

    let controls = CacheCurrentAuditOriginalsV1::receiving_control_bytes_v1()
        .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(CacheHeldErrorV1::Order)?;
    Ok(receiving::current_fixed_demand()?.with(D::MetadataEntries, 0)
        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, controls))?)
}
