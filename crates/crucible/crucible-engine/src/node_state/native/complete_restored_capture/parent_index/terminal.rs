//! Admits each actual parent reader constructor beneath its exact Index3 key.

use super::*;

/// Keeps previously observed cache totals without walking them before precredit.
pub(super) struct ParentTerminal17<'a> {
    source: RestoredArchive17SourceIndex,
    depth: usize,
    reference: &'a ContentRef,
    enclosing_cache: usize,
    cache: usize,
}

impl<'a> ParentTerminal17<'a> {
    pub(super) fn new_data(
        source: RestoredArchive17SourceIndex,
        depth: usize,
        reference: &'a ContentRef,
        enclosing_cache: usize,
    ) -> Self {
        Self {
            source,
            depth,
            reference,
            enclosing_cache,
            cache: enclosing_cache,
        }
    }

    fn step_data(
        &self,
        work: RestoredArchive17ParentWork,
    ) -> Result<RestoredArchive17ValidationStep, StateError> {
        RestoredArchive17ValidationStep::parent_data(self.source, self.depth, self.reference, work)
    }

    pub(super) fn begin_data(
        &self,
        scope: &CompleteRestoredSettledArchiveValidation<'_>,
        work: RestoredArchive17ParentWork,
        scratch: usize,
    ) -> Result<(), StateError> {
        if let Some(admission) = scope.terminal_admission_data() {
            admission.begin_stage_data(RestoredArchive17ValidationPrewalkData::new_data(
                self.step_data(work)?,
                self.cache,
                0,
                scratch,
            )?)?;
        }
        scope.validation_origin.authenticate(scope.archive)
    }

    pub(super) fn construct_data(
        &self,
        scope: &CompleteRestoredSettledArchiveValidation<'_>,
        work: RestoredArchive17ParentWork,
        retained: usize,
        transient: usize,
        scratch: usize,
    ) -> Result<(), StateError> {
        if let Some(admission) = scope.terminal_admission_data() {
            admission.construct_stage_data(
                RestoredArchive17ValidationConstructionData::new_data(
                    self.step_data(work)?,
                    self.cache,
                    retained,
                    transient,
                    scratch,
                )?,
            )?;
        }
        scope.validation_origin.authenticate(scope.archive)
    }

    /// Counts the newly retained parent only inside the admitted census S.
    pub(super) fn finish_data(
        &mut self,
        scope: &CompleteRestoredSettledArchiveValidation<'_>,
        work: RestoredArchive17ParentWork,
        attempt: &ParentIndex17Attempt,
    ) -> Result<(), StateError> {
        let cache = self
            .enclosing_cache
            .checked_add(
                attempt
                    .retained_requested_storage_data(maximum(scope)?)
                    .map_err(super::super::super::super::schema)?,
            )
            .ok_or_else(|| refused("parent terminal cache overflow"))?;
        if let Some(admission) = scope.terminal_admission_data() {
            admission.finish_stage_data(self.step_data(work)?, cache)?;
        }
        self.cache = cache;
        scope.validation_origin.authenticate(scope.archive)
    }

    pub(super) fn completed_cache_data(&self) -> usize {
        self.cache
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<ParentTerminal17<'static>>()
        + size_of::<RestoredArchive17ParentWork>()
        + size_of::<RestoredArchive17ValidationStep>()
        + size_of::<RestoredArchive17ValidationPrewalkData>()
        + size_of::<RestoredArchive17ValidationConstructionData>()
        + size_of::<Result<RestoredArchive17ValidationStep, StateError>>()
        + size_of::<Result<RestoredArchive17ValidationPrewalkData, StateError>>()
        + size_of::<Result<RestoredArchive17ValidationConstructionData, StateError>>()
        + size_of::<Result<usize, StateError>>()
        + size_of::<Result<(), StateError>>()
}
