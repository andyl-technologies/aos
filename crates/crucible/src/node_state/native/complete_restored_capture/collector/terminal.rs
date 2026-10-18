//! Admits actual cold-reader constructors beside all previously live caches.
//!
//! The saved cache total is operational accounting DATA. It is refreshed only
//! inside an admitted constructor's fixed census workspace. It never supplies
//! membership, native history, Source authenticity or restoration permission.

use super::*;
use super::super::terminal::{
    RestoredArchive17ValidationConstructionData, RestoredArchive17ValidationPrewalkData,
    RestoredArchive17ValidationStep,
};

pub(super) fn terminal_cache_seed(
    scope: &CompleteRestoredSettledArchiveValidation<'_>,
    additional: usize,
) -> Result<usize, StateError> {
    scope
        .terminal_prefix_retained_storage_data()?
        .checked_add(additional)
        .and_then(|bytes| bytes.checked_add(size_of::<Option<RetainedCold17Collection>>()))
        .ok_or_else(|| refused("cold17 terminal cache seed overflow"))
}

impl RetainedCold17Collection {
    /// Admits the quote's actual nonallocating walk before entering it.
    pub(super) fn begin_terminal_stage_data(
        &self,
        scope: &CompleteRestoredSettledArchiveValidation<'_>,
        step: RestoredArchive17ValidationStep,
        transient: usize,
        scratch: usize,
    ) -> Result<(), StateError> {
        self.authenticate_archive_data(scope.archive)
            .map_err(super::super::super::super::schema)?;
        if let Some(admission) = scope.terminal_admission_data() {
            admission.begin_stage_data(RestoredArchive17ValidationPrewalkData::new_data(
                step,
                self.terminal_cache,
                transient,
                scratch,
            )?)?;
        }
        scope.validation_origin.authenticate(scope.archive)
    }

    /// Admits the actual constructor before its first owning operation.
    pub(super) fn construct_terminal_stage_data(
        &self,
        scope: &CompleteRestoredSettledArchiveValidation<'_>,
        step: RestoredArchive17ValidationStep,
        retained: usize,
        transient: usize,
        scratch: usize,
    ) -> Result<(), StateError> {
        self.authenticate_archive_data(scope.archive)
            .map_err(super::super::super::super::schema)?;
        if let Some(admission) = scope.terminal_admission_data() {
            admission.construct_stage_data(
                RestoredArchive17ValidationConstructionData::new_data(
                    step,
                    self.terminal_cache,
                    retained,
                    transient,
                    scratch,
                )?,
            )?;
        }
        scope.validation_origin.authenticate(scope.archive)
    }

    /// Saves actual retained capacity while the constructor census row is live.
    pub(super) fn finish_terminal_stage_data(
        &mut self,
        scope: &CompleteRestoredSettledArchiveValidation<'_>,
        step: RestoredArchive17ValidationStep,
        additional: usize,
    ) -> Result<(), StateError> {
        let retained = terminal_cache_seed(scope, additional)?
            .checked_add(
                self.retained_requested_storage_data(maximum(scope)?)
                    .map_err(super::super::super::super::schema)?,
            )
            .ok_or_else(|| refused("cold17 actual terminal cache overflow"))?;
        if let Some(admission) = scope.terminal_admission_data() {
            admission.finish_stage_data(step, retained)?;
        }
        self.terminal_cache = retained;
        scope.validation_origin.authenticate(scope.archive)
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<RestoredArchive17ValidationStep>()
        + size_of::<RestoredArchive17ValidationPrewalkData>()
        + size_of::<RestoredArchive17ValidationConstructionData>()
        + size_of::<Result<RestoredArchive17ValidationPrewalkData, StateError>>()
        + size_of::<Result<RestoredArchive17ValidationConstructionData, StateError>>()
        + size_of::<Result<usize, StateError>>()
        + size_of::<Result<(), StateError>>()
}
