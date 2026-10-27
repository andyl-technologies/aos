//! Closes actual Cache custody beside the same completed C10 and Root6.
//!
//! The native owner retains all writer, physical, clock and selection posts.
//! This programme retains the genuine upper entry/currentness/paired-clock
//! results and their first cause. No earlier refusal suppresses owed posts.

use super::*;
use crate::controller_resource_reservation::CacheTerminalReceivingLoanV1;

#[derive(Default)]
pub(super) struct CacheTerminalOriginalsV1 {
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    current: Option<Result<(), ResourceReservationErrorV1>>,
    selected_control: bool,
    clock_original: crate::policy_compiler::RetainedKernelPairedClockAttemptV1,
    clock: Option<Result<aos_sandbox_model::RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
    cutoff: Option<Result<(), ResourceReservationErrorV1>>,
}

impl CacheTerminalOriginalsV1 {
    pub(super) fn failure<'cause>(
        &'cause self,
        native_failure: Option<&'cause (dyn Error + 'static)>,
    ) -> Option<&'cause (dyn Error + 'static)> {
        error(&self.entry)
            .or(native_failure)
            .or_else(|| error(&self.current))
            .or_else(|| self.clock_original.failure())
            .or_else(|| error(&self.clock))
            .or_else(|| error(&self.cutoff))
    }
}

/// Prices the original upper terminal and its actual separate native posts.
///
/// The existing genuine U release entry includes this complete demand before
/// allocating either Box. The native quote covers the split native destination
/// and its new method-return carriers; this covers the real upper clock backing.
///
/// # Errors
/// Rejects checked representation or resource-vector arithmetic overflow.
pub(crate) fn cache_terminal_receiving_demand_v1() -> Result<ResourceVector, CacheHeldErrorV1> {
    use aos_sandbox_model::ResourceDimension as D;

    // These immediate closures borrow distinct source places. Their capture
    // construction and FnOnce receivers coexist with the separate results.
    let entry_capture = std::mem::size_of::<(
        &Option<Failure>,
        &NativeCreateStorageCacheLoanV1<'_>,
        &Result<(), CacheHeldClosedV1>,
        &mut CacheTerminalReceivingLoanV1<'_, '_>,
    )>();
    let cutoff_capture = std::mem::size_of::<(
        &CacheTerminalOriginalsV1,
        &mut CacheTerminalReceivingLoanV1<'_, '_>,
    )>();
    let bytes = std::mem::size_of::<CacheTerminalOriginalsV1>()
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(std::mem::align_of::<CacheTerminalOriginalsV1>()))
        .and_then(|bytes| bytes.checked_add(crate::policy_compiler::RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<(
            Option<Box<CacheTerminalOriginalsV1>>,
            Option<Result<(), ResourceReservationErrorV1>>,
        )>().checked_mul(2)?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Box<CacheTerminalOriginalsV1>>()))
        .and_then(|bytes| bytes.checked_add(
            std::mem::size_of::<Result<(), CacheHeldClosedV1>>().checked_mul(3)?,
        ))
        .and_then(|bytes| bytes.checked_add(
            std::mem::size_of::<Option<&(dyn Error + 'static)>>().checked_mul(3)?,
        ))
        // Entry, upper currentness and cutoff each construct/return/retain a
        // separate status; the actual paired-clock result and copied sample
        // remain live while the cutoff closure validates the same sample.
        .and_then(|bytes| bytes.checked_add(
            std::mem::size_of::<Result<(), ResourceReservationErrorV1>>().checked_mul(9)?,
        ))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
            Result<aos_sandbox_model::RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>,
        >().checked_mul(3)?))
        .and_then(|bytes| bytes.checked_add(
            std::mem::size_of::<aos_sandbox_model::RawPairedClockSample>().checked_mul(3)?,
        ))
        .and_then(|bytes| bytes.checked_add(entry_capture.checked_mul(2)?))
        .and_then(|bytes| bytes.checked_add(cutoff_capture.checked_mul(2)?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<[bool; 4]>()))
        .ok_or(CacheHeldErrorV1::Order)?;
    ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| CacheHeldErrorV1::Order)?)
        .with(D::OpenFiles, u64::try_from(crate::policy_compiler::RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1)
            .map_err(|_| CacheHeldErrorV1::Order)?)
        .checked_add(NativeCreateStorageCacheLoanV1::terminal_receiving_demand_v1()?)
        .map_err(Into::into)
}

impl OriginalCreateStorageCacheLoanV1<'_> {
    pub(crate) fn finish_original_create_storage_after_root_v1(
        &mut self,
        receiving: &mut CacheTerminalReceivingLoanV1<'_, '_>,
    ) -> Result<(), CacheHeldClosedV1> {
        if self.progress.terminal.is_some() || self.progress.root.is_some() {
            self.progress.refuse();
            return Err(CacheHeldClosedV1);
        }
        self.progress.terminal = Some(Box::new(CacheTerminalOriginalsV1::default()));
        self.select_native_failure();
        let native_entry = self.native.prepare_terminal_native_once_v1();
        let entry = (|| {
            if self.progress.first.is_some() || native_entry.is_err() {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            receiving.require_original_v1(self.native.original_identity_v1())
        })();
        self.progress.terminal.as_deref_mut().ok_or(CacheHeldClosedV1)?.entry = Some(entry);

        let released = receiving.released_original_v1().ok().map(|released| &released.native);
        let native_posts = self.native.observe_terminal_native_posts_once_v1(released);
        // Entry/native-post refusal cannot suppress this same paid C/Source IO.
        let current = receiving.observe_currentness_once(self);
        let terminal = self.progress.terminal.as_deref_mut().ok_or(CacheHeldClosedV1)?;
        terminal.selected_control = matches!(terminal.entry, Some(Ok(())))
            && native_posts.is_ok() && current.is_err();
        terminal.current = Some(current);
        terminal.clock = Some(terminal.clock_original.observe_once(None));
        terminal.cutoff = Some((|| {
            let actual = terminal.clock.as_ref().and_then(|result| result.as_ref().ok()).copied()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            receiving.clock_v1()?.validate_later_sample(actual)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            if actual.boottime_nanoseconds() >= receiving.cutoff_v1()? {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(())
        })());
        let complete = terminal.failure(self.native.failure()).is_none()
            && matches!(terminal.cutoff, Some(Ok(())));
        let completed = if complete {
            self.native.finish_terminal_native_once_v1().is_ok()
        } else {
            self.native.reject_terminal_upper_v1();
            false
        };
        self.progress.root = Some(if completed { Ok(()) } else { Err(ResourceReservationErrorV1::Conflict) });
        if !completed {
            self.progress.fail(Failure::Root);
            Err(CacheHeldClosedV1)
        } else {
            Ok(())
        }
    }

    pub(crate) fn terminal_control_is_selected_v1(&self) -> bool {
        self.progress.terminal.as_deref().is_some_and(|terminal| terminal.selected_control)
    }
}

impl CacheResidentInitializationV1 {
    /// Requires the same upper Root6 result and its completed native originals.
    ///
    /// This is the Root continuation half of Delete entry. Ordinary initialized
    /// entry remains a separate native predicate and no Initial Create loan is
    /// borrowed again. A copied terminal receipt cannot satisfy this check.
    ///
    /// # Errors
    /// Refuses upper debt, missing/failed actual Root6 or incomplete native custody.
    pub(crate) fn require_create_storage_terminal_v1(&self) -> Result<(), CacheHeldClosedV1> {
        if self.failure().is_some() || !matches!(self.create_storage_held.root, Some(Ok(()))) {
            return Err(CacheHeldClosedV1);
        }
        self.native.require_create_storage_terminal_native_v1()
    }
}
