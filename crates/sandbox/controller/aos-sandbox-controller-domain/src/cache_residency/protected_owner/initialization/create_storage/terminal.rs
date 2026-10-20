//! Retains the last native Cache post until genuine Root6 closes the originals.
//!
//! The five writer, physical, clock and selection observations share the same
//! engine as earlier held-owner posts. Failed terminal custody stays armed.

use super::*;
use crate::controller_resource_reservation::CacheTerminalReceivingLoanV1;

#[derive(Default)]
pub(super) struct CacheTerminalOriginalsV1 {
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    posts: Option<audit::CacheHeldBookendsV1>,
    current: Option<Result<(), ResourceReservationErrorV1>>,
    selected_control: bool,
    clock_original: crate::policy_compiler::RetainedKernelPairedClockAttemptV1,
    clock: Option<Result<aos_sandbox_model::RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
    cutoff: Option<Result<(), ResourceReservationErrorV1>>,
}

impl CacheTerminalOriginalsV1 {
    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.entry).or_else(|| self.posts.as_ref().and_then(audit::CacheHeldBookendsV1::failure))
            .or_else(|| error(&self.current)).or_else(|| self.clock_original.failure())
            .or_else(|| error(&self.clock)).or_else(|| error(&self.cutoff))
    }
}

pub(crate) fn cache_terminal_receiving_demand_v1() -> Result<ResourceVector, CacheHeldErrorV1> {
    use aos_sandbox_model::ResourceDimension as D;
    let bytes = std::mem::size_of::<CacheTerminalOriginalsV1>().checked_mul(2)
        .and_then(|bytes| bytes.checked_add(std::mem::align_of::<CacheTerminalOriginalsV1>()))
        .and_then(|bytes| bytes.checked_add(crate::policy_compiler::RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()?))
        .ok_or(CacheHeldErrorV1::Order)?;
    ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| CacheHeldErrorV1::Order)?)
        .with(D::OpenFiles, u64::try_from(crate::policy_compiler::RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1)
            .map_err(|_| CacheHeldErrorV1::Order)?).checked_add(ResourceVector::ZERO).map_err(Into::into)
}

impl OriginalCreateStorageCacheLoanV1<'_> {
    pub(crate) fn finish_original_create_storage_after_root_v1(&mut self,
        receiving: &mut CacheTerminalReceivingLoanV1<'_, '_>,
    ) -> Result<(), CacheHeldClosedV1> {
        if self.progress.terminal.is_some() || self.progress.root.is_some() || self.progress.finished {
            self.progress.refuse();
            return Err(CacheHeldClosedV1);
        }
        // The real U funded this concrete backing at Cache release entry.
        self.progress.terminal = Some(Box::new(CacheTerminalOriginalsV1::default()));
        let entry = (|| {
            if self.progress.first.is_some() || self.progress.audit_next != 15
                || self.progress.active_audit.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
            receiving.require_original_v1(self.identity)
        })();
        self.progress.terminal.as_deref_mut().ok_or(CacheHeldClosedV1)?.entry = Some(entry);
        let expected = receiving.released_original_v1().ok()
            .and_then(|original| original.after_hold_shape_v1());
        let posts = audit::observe_bookends_with_hold_v1(&mut self.originals, self.progress, None, expected);
        self.progress.terminal.as_deref_mut().ok_or(CacheHeldClosedV1)?.posts = Some(posts);
        // This independent same-C/Source/profile observation was already paid.
        // Native entry or Cache-post failure cannot suppress its actual IO.
        let current = receiving.observe_currentness_once(self);
        let terminal = self.progress.terminal.as_deref_mut().ok_or(CacheHeldClosedV1)?;
        terminal.selected_control = matches!(terminal.entry, Some(Ok(())))
            && terminal.posts.as_ref().is_some_and(|posts| posts.failure().is_none()) && current.is_err();
        terminal.current = Some(current);
        terminal.clock = Some(terminal.clock_original.observe_once(None));
        terminal.cutoff = Some((|| {
            let actual = terminal.clock.as_ref().and_then(|result| result.as_ref().ok()).copied()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            receiving.clock_v1()?.validate_later_sample(actual).map_err(|_| ResourceReservationErrorV1::Conflict)?;
            if actual.boottime_nanoseconds() >= receiving.cutoff_v1()? {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(())
        })());
        let complete = terminal.failure().is_none() && matches!(terminal.cutoff, Some(Ok(())));
        self.progress.root = Some(if complete { Ok(()) } else { Err(ResourceReservationErrorV1::Conflict) });
        self.progress.mark(!complete, Failure::Root);
        if complete {
            // Only the actual complete terminal and every owed post permit
            // the original clock/writer guard's eventual positive disposal.
            self.progress.finished = true;
            Ok(())
        } else { Err(CacheHeldClosedV1) }
    }

    pub(crate) fn terminal_control_is_selected_v1(&self) -> bool {
        self.progress.terminal.as_deref().is_some_and(|terminal| terminal.selected_control)
    }
}
