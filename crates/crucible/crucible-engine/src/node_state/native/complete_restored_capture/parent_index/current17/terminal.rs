//! Borrows the top writer's real terminal ledger for exact parent header phases.

use super::*;
use std::cell::Cell;

pub(super) struct ParentHeaderTerminal17<'borrow, 'archive> {
    current: &'borrow CompleteRestoredSettledArchiveValidation<'archive>,
    parent: &'borrow ContentRef,
    source: RestoredArchive17SourceIndex,
    depth: usize,
    prior: usize,
    completed: Cell<usize>,
    active: Cell<Option<RestoredArchive17ValidationStep>>,
    constructed: Cell<bool>,
}

impl<'borrow, 'archive> ParentHeaderTerminal17<'borrow, 'archive> {
    pub(super) fn new_data(
        current: &'borrow CompleteRestoredSettledArchiveValidation<'archive>,
        parent: &'borrow ParentArchive17ReadScope<'_, '_>,
        source: RestoredArchive17SourceIndex,
        depth: usize,
        prior: usize,
    ) -> Result<Self, StateError> {
        if !std::ptr::eq(current, parent.validation) {
            return Err(refused(
                "parent header admission belongs to another top archive occurrence",
            ));
        }
        current.validation_origin.authenticate(current.archive)?;
        Ok(Self {
            current,
            parent: parent.index_reference_data()?,
            source,
            depth,
            prior,
            completed: Cell::new(prior),
            active: Cell::new(None),
            constructed: Cell::new(false),
        })
    }

    pub(super) fn begin_data(&self, work: Work, transient: usize) -> Result<(), StateError> {
        if self.active.get().is_some() {
            return Err(refused("parent header prior constructor is still active"));
        }
        let step = RestoredArchive17ValidationStep::parent_data(
            self.source,
            self.depth,
            self.parent,
            RestoredArchive17ParentWork::Current17Header(work),
        )?;
        self.active.set(Some(step));
        if let Some(admission) = self.current.terminal_admission_data() {
            admission.begin_stage_data(RestoredArchive17ValidationPrewalkData::new_data(
                step,
                self.completed.get(),
                transient,
                ParentCurrent17HeaderAttempt::counter_scratch_data(),
            )?)?;
        }
        Ok(())
    }

    pub(super) fn construct_data(
        &self,
        growth: usize,
        transient: usize,
        scratch: usize,
    ) -> Result<(), StateError> {
        let step = self
            .active
            .get()
            .ok_or_else(|| refused("parent header prewalk absent"))?;
        if self.constructed.replace(true) {
            return Err(refused("parent header constructor is already spent"));
        }
        let scratch = scratch
            .checked_add(ParentCurrent17HeaderAttempt::counter_scratch_data())
            .ok_or_else(|| refused("parent header fixed workspace overflow"))?;
        if let Some(admission) = self.current.terminal_admission_data() {
            admission.construct_stage_data(
                RestoredArchive17ValidationConstructionData::new_data(
                    step,
                    self.completed.get(),
                    growth,
                    transient,
                    scratch,
                )?,
            )?;
        }
        Ok(())
    }

    pub(super) fn finish_data(
        &self,
        owner: &ParentCurrent17HeaderAttempt,
        parent: &ParentArchive17ReadScope<'_, '_>,
    ) -> Result<(), StateError> {
        let step = self
            .active
            .get()
            .ok_or_else(|| refused("parent header constructor absent"))?;
        if !self.constructed.get() {
            return Err(refused("parent header constructor was not admitted"));
        }
        owner.authenticate_parent_data(parent)?;
        let backing = owner
            .retained_requested_storage_data(owner.maximum)
            .map_err(schema)?
            .checked_sub(size_of::<ParentCurrent17HeaderAttempt>())
            .ok_or_else(|| refused("parent header inline census overflow"))?;
        let actual = self
            .prior
            .checked_add(backing)
            .ok_or_else(|| refused("parent header completed cache overflow"))?;
        if let Some(admission) = self.current.terminal_admission_data() {
            admission.finish_stage_data(step, actual)?;
        }
        owner.authenticate_parent_data(parent)?;
        self.completed.set(actual);
        self.active.set(None);
        self.constructed.set(false);
        Ok(())
    }

    pub(super) fn completed_cache_data(&self) -> Result<usize, StateError> {
        if self.active.get().is_some() {
            return Err(refused("parent header constructor did not finish"));
        }
        Ok(self.completed.get())
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<RestoredArchive17ValidationStep>()
        + size_of::<Option<RestoredArchive17ValidationStep>>()
        + size_of::<RestoredArchive17ValidationPrewalkData>()
        + size_of::<RestoredArchive17ValidationConstructionData>()
        + size_of::<Option<&dyn super::super::super::terminal::RestoredArchive17ValidationAdmission>>(
        )
        + size_of::<Result<RestoredArchive17ValidationStep, StateError>>()
        + size_of::<Result<(), StateError>>()
}
