//! Bridges actual Provider cold constructors to the real terminal Window rows.
//!
//! Provider rows contain numeric layout DATA. The adapter separately binds them
//! to this actual archive occurrence, Source slot and completed cache chronology.

use super::*;
use super::super::terminal::{
    RestoredArchive17ValidationAdmission, RestoredArchive17ValidationConstructionData,
    RestoredArchive17ValidationPrewalkData,
};
use crucible_node_provider::{
    ProviderError,
    protocol_snapshot::restored_settled17::{
        NativeCold17Admission, NativeCold17ConstructionData, NativeCold17PrewalkData,
        NativeCold17Work,
    },
};
use std::cell::Cell;

/// Binds one actual Provider constructor sequence to its genuine Source slot.
pub(super) struct NativeTerminal17<'scope, 'archive> {
    scope: &'scope CompleteRestoredSettledArchiveValidation<'archive>,
    admission: &'scope dyn RestoredArchive17ValidationAdmission,
    source: RestoredArchive17SourceIndex,
    other_cache: usize,
    native_cache: Cell<usize>,
    last: Cell<Option<NativeCold17Work>>,
    pending: Cell<Option<NativeCold17Work>>,
    constructed: Cell<bool>,
}

impl<'scope, 'archive> NativeTerminal17<'scope, 'archive> {
    /// Borrows this exact terminal scope without constructing Provider authority.
    ///
    /// # Errors
    /// Refuses a historical/nonterminal scope or a changed archive origin.
    pub(super) fn new_data(
        scope: &'scope CompleteRestoredSettledArchiveValidation<'archive>,
        source: RestoredArchive17SourceIndex,
        other_cache: usize,
    ) -> Result<Self, StateError> {
        let admission = scope
            .terminal_admission_data()
            .ok_or_else(|| refused("cold17 native terminal admission absent"))?;
        scope.validation_origin.authenticate(scope.archive)?;
        Ok(Self {
            scope,
            admission,
            source,
            other_cache,
            native_cache: Cell::new(0),
            last: Cell::new(None),
            pending: Cell::new(None),
            constructed: Cell::new(false),
        })
    }

    fn step_data(&self, work: NativeCold17Work) -> RestoredArchive17ValidationStep {
        RestoredArchive17ValidationStep::native_data(self.source, work)
    }

    fn total_data(&self, native: usize) -> Result<usize, ProviderError> {
        self.other_cache
            .checked_add(native)
            .ok_or_else(provider_refusal)
    }

    fn authenticate_data(&self) -> Result<(), ProviderError> {
        self.scope
            .validation_origin
            .authenticate(self.scope.archive)
            .map_err(|_| provider_refusal())
    }

    fn callback_data(&self, result: Result<(), StateError>) -> Result<(), ProviderError> {
        // Preserve the post-guard on both callback outcomes. Static conversion
        // adds no boxed error/formatter allocation to the Provider boundary.
        self.authenticate_data()?;
        result.map_err(|_| provider_refusal())
    }

    /// Returns the actual total only after the final Provider constructor finished.
    ///
    /// # Errors
    /// Refuses unfinished work, foreign origin or checked cache overflow.
    pub(super) fn completed_cache_data(&self) -> Result<usize, StateError> {
        if self.last.get() != Some(NativeCold17Work::RestorationHold)
            || self.pending.get().is_some()
            || self.constructed.get()
        {
            return Err(refused("cold17 native constructor sequence is incomplete"));
        }
        self.scope
            .validation_origin
            .authenticate(self.scope.archive)?;
        self.other_cache
            .checked_add(self.native_cache.get())
            .ok_or_else(|| refused("cold17 completed native cache overflow"))
    }
}

impl NativeCold17Admission for NativeTerminal17<'_, '_> {
    fn begin_data(&self, prewalk: NativeCold17PrewalkData) -> Result<(), ProviderError> {
        self.authenticate_data()?;
        let work = prewalk.work_data();
        if self.pending.get().is_some()
            || !work.follows_data(self.last.get())
            || prewalk.prior_native_cache_retained_bytes_data() != self.native_cache.get()
        {
            return Err(provider_refusal());
        }
        let scratch = prewalk
            .counter_scratch_bytes_data()
            .checked_add(counter_scratch_data())
            .ok_or_else(provider_refusal)?;
        let row = RestoredArchive17ValidationPrewalkData::new_data(
            self.step_data(work),
            self.total_data(self.native_cache.get())?,
            prewalk.quote_transient_bytes_data(),
            scratch,
        )
        .map_err(|_| provider_refusal())?;
        self.callback_data(self.admission.begin_stage_data(row))?;
        self.pending.set(Some(work));
        Ok(())
    }

    fn construct_data(&self, data: NativeCold17ConstructionData) -> Result<(), ProviderError> {
        self.authenticate_data()?;
        let work = data.work_data();
        if self.pending.get() != Some(work)
            || self.constructed.get()
            || data.prior_native_cache_retained_bytes_data() != self.native_cache.get()
        {
            return Err(provider_refusal());
        }
        let scratch = data
            .counter_scratch_bytes_data()
            .checked_add(counter_scratch_data())
            .ok_or_else(provider_refusal)?;
        let row = RestoredArchive17ValidationConstructionData::new_data(
            self.step_data(work),
            self.total_data(self.native_cache.get())?,
            data.maximum_new_retained_bytes_data(),
            data.constructor_transient_bytes_data(),
            scratch,
        )
        .map_err(|_| provider_refusal())?;
        self.callback_data(self.admission.construct_stage_data(row))?;
        self.constructed.set(true);
        Ok(())
    }

    fn finish_data(&self, work: NativeCold17Work, actual: usize) -> Result<(), ProviderError> {
        self.authenticate_data()?;
        if self.pending.get() != Some(work) || !self.constructed.get() {
            return Err(provider_refusal());
        }
        self.callback_data(
            self.admission
                .finish_stage_data(self.step_data(work), self.total_data(actual)?),
        )?;
        self.native_cache.set(actual);
        self.last.set(Some(work));
        self.pending.set(None);
        self.constructed.set(false);
        Ok(())
    }
}

fn provider_refusal() -> ProviderError {
    ProviderError::ResourceExhausted("cold17 terminal constructor admission")
}

/// Names actual adapter, typed phase and callback-result controls.
pub(super) fn counter_scratch_data() -> usize {
    size_of::<NativeTerminal17<'static, 'static>>()
        + size_of::<RestoredArchive17ValidationStep>()
        + size_of::<RestoredArchive17ValidationPrewalkData>()
        + size_of::<RestoredArchive17ValidationConstructionData>()
        + size_of::<NativeCold17Work>()
        + size_of::<NativeCold17PrewalkData>()
        + size_of::<NativeCold17ConstructionData>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<(), StateError>>()
}
