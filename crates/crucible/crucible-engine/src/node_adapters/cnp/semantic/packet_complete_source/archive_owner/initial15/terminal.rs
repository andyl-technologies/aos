//! Borrows the actual enclosing writer's append-only constructor boundaries.
//!
//! This temporary cursor carries accounting DATA and a real borrowed observer.
//! It is never stored in historical output, serialized or converted to authority.
//! Failed phases remain spent in the enclosing Window's actual terminal ledger.

use super::*;
use crate::node_state::{
    CompleteRestoredSettledArchiveValidation, RestoredArchive17Initial15Work,
    RestoredArchive17ParentWork, RestoredArchive17SourceIndex,
    RestoredArchive17ValidationConstructionData, RestoredArchive17ValidationPrewalkData,
    RestoredArchive17ValidationStep,
};
use std::cell::Cell;

#[path = "terminal/launch.rs"]
mod launch;
#[path = "terminal/protocol.rs"]
mod protocol;
#[path = "terminal/runtime.rs"]
mod runtime;
#[path = "terminal/semantic_join.rs"]
mod semantic_join;

pub(in crate::node_adapters::cnp::semantic::packet_complete_source::archive_owner) struct Initial15Terminal17<
    'borrow,
    'archive,
> {
    current: &'borrow CompleteRestoredSettledArchiveValidation<'archive>,
    parent: &'borrow ContentRef,
    source: RestoredArchive17SourceIndex,
    depth: usize,
    prior_cache: usize,
    completed_cache: Cell<usize>,
    active: Cell<Option<RestoredArchive17ValidationStep>>,
    constructed: Cell<bool>,
}

impl<'borrow, 'archive> Initial15Terminal17<'borrow, 'archive> {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::archive_owner) fn new_data(
        current: &'borrow CompleteRestoredSettledArchiveValidation<'archive>,
        parent: &'borrow ParentArchive17ReadScope<'_, '_>,
        source: RestoredArchive17SourceIndex,
        depth: usize,
        prior_cache: usize,
    ) -> Result<Self, OperationFailure> {
        Ok(Self {
            current,
            parent: parent.index_reference_data().map_err(unknown)?,
            source,
            depth,
            prior_cache,
            completed_cache: Cell::new(prior_cache),
            active: Cell::new(None),
            constructed: Cell::new(false),
        })
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::archive_owner) fn begin_data(
        &self,
        work: RestoredArchive17Initial15Work,
        transient: usize,
    ) -> Result<(), OperationFailure> {
        self.begin_with_scratch_data(work, transient, 0)
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::archive_owner) fn begin_with_scratch_data(
        &self,
        work: RestoredArchive17Initial15Work,
        transient: usize,
        additional_scratch: usize,
    ) -> Result<(), OperationFailure> {
        if self.active.get().is_some() {
            return Err(refused("initial15 terminal constructor still active"));
        }
        let step = RestoredArchive17ValidationStep::parent_data(
            self.source,
            self.depth,
            self.parent,
            RestoredArchive17ParentWork::Initial15(work),
        )
        .map_err(unknown)?;
        // A refusal must not make the cursor reusable. The real observer owns
        // the durable numeric refusal; this local cell also retains the phase.
        self.active.set(Some(step));
        if let Some(admission) = self.current.terminal_admission_data() {
            admission
                .begin_stage_data(
                    RestoredArchive17ValidationPrewalkData::new_data(
                        step,
                        self.completed_cache.get(),
                        transient,
                        Self::counter_scratch_data()
                            .checked_add(additional_scratch)
                            .ok_or_else(|| refused("initial15 terminal fixed scratch overflow"))?,
                    )
                    .map_err(unknown)?,
                )
                .map_err(unknown)?;
        }
        Ok(())
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::archive_owner) fn construct_data(
        &self,
        retained_growth: usize,
        transient: usize,
    ) -> Result<(), OperationFailure> {
        self.construct_with_scratch_data(retained_growth, transient, 0)
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::archive_owner) fn construct_with_scratch_data(
        &self,
        retained_growth: usize,
        transient: usize,
        additional_scratch: usize,
    ) -> Result<(), OperationFailure> {
        let step = self
            .active
            .get()
            .ok_or_else(|| refused("initial15 terminal prewalk absent"))?;
        if self.constructed.replace(true) {
            return Err(refused("initial15 terminal constructor already spent"));
        }
        if let Some(admission) = self.current.terminal_admission_data() {
            admission
                .construct_stage_data(
                    RestoredArchive17ValidationConstructionData::new_data(
                        step,
                        self.completed_cache.get(),
                        retained_growth,
                        transient,
                        Self::counter_scratch_data()
                            .checked_add(additional_scratch)
                            .ok_or_else(|| refused("initial15 terminal fixed scratch overflow"))?,
                    )
                    .map_err(unknown)?,
                )
                .map_err(unknown)?;
        }
        Ok(())
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::archive_owner) fn finish_data(
        &self,
        group: &OriginalInitial15ArchivedGroup,
        temporary_backing: usize,
    ) -> Result<(), OperationFailure> {
        // The caller has already released the actual constructor loans and
        // checked its defining guards. Census work is inside that funded row.
        let backing = group
            .retained_requested_storage_data(group.maximum)?
            .checked_sub(size_of::<OriginalInitial15ArchivedGroup>())
            .and_then(|bytes| bytes.checked_add(temporary_backing))
            .ok_or_else(|| refused("initial15 actual terminal backing overflow"))?;
        self.finish_requested_data(backing)
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::archive_owner) fn finish_requested_data(
        &self,
        backing: usize,
    ) -> Result<(), OperationFailure> {
        let step = self
            .active
            .get()
            .ok_or_else(|| refused("initial15 terminal constructor absent"))?;
        if !self.constructed.get() {
            return Err(refused("initial15 terminal constructor was not admitted"));
        }
        let actual = self
            .prior_cache
            .checked_add(backing)
            .ok_or_else(|| refused("initial15 terminal actual cache overflow"))?;
        if let Some(admission) = self.current.terminal_admission_data() {
            admission.finish_stage_data(step, actual).map_err(unknown)?;
        }
        self.completed_cache.set(actual);
        self.active.set(None);
        self.constructed.set(false);
        Ok(())
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::archive_owner) fn completed_cache_data(
        &self,
    ) -> Result<usize, OperationFailure> {
        if self.active.get().is_some() {
            return Err(refused("initial15 terminal construction incomplete"));
        }
        Ok(self.completed_cache.get())
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::archive_owner) fn counter_scratch_data()
    -> usize {
        size_of::<Self>()
            + size_of::<Result<Self, OperationFailure>>()
            + size_of::<Option<&Self>>()
            + size_of::<Option<&dyn crate::node_state::RestoredArchive17ValidationAdmission>>()
            + size_of::<Result<usize, OperationFailure>>()
            + size_of::<Option<RestoredArchive17ValidationStep>>()
            + size_of::<RestoredArchive17ValidationPrewalkData>()
            + size_of::<RestoredArchive17ValidationConstructionData>()
            + size_of::<Result<RestoredArchive17ValidationStep, crate::node_state::StateError>>()
            + size_of::<Result<(), crate::node_state::StateError>>()
            + size_of::<Result<(), OperationFailure>>()
            + OriginalInitial15ArchivedGroup::counter_scratch_data()
            + runtime::counter_scratch_data()
            + launch::counter_scratch_data()
            + protocol::counter_scratch_data()
            + OriginalInitial15ArchivedGroup::semantic_join_terminal_counter_scratch_data()
    }
}

pub(super) use protocol::protocol_prepare_terminal_storage_data;
