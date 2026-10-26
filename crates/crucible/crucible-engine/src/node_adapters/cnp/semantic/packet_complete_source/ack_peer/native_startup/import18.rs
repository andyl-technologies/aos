//! Retains the import18 finalization header and its actual storage observers.
//!
//! The complete writer remains unselected until its unchanged pre-report
//! SourceBirth6..12 bank and exact borrowed declaration view have a genuine,
//! independently funded producer. Legacy report DOM is never relabeled as that
//! view. These retained fields, census and cursor controls create no member.

use super::*;
use crate::node_admission::OriginalNativeImport18StartupMember;
use std::cell::Cell;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in super::super) enum Import18WireStage {
    Unused,
    Retaining,
    Prepared,
    Publishing,
    Complete,
}

pub(in super::super) struct OriginalNativeImport18Finalization {
    pub(in super::super) member: OriginalNativeImport18StartupMember,
    baseline: Option<serde_json::Value>,
    additions: Option<serde_json::Value>,
    wrapper: Option<serde_json::Value>,
    replacement: Vec<u8>,
    prepared: bool,
    pub(in super::super) complete: bool,
    wire: Cell<Import18WireStage>,
}

impl OriginalNativeImport18Finalization {
    pub(in super::super) fn source_binding_data(&self) -> Result<&serde_json::Value, RuntimeError> {
        if !self.prepared || !self.complete {
            return Err(RuntimeError::OwnerUnavailable);
        }
        self.wrapper.as_ref().ok_or(RuntimeError::OwnerUnavailable)
    }

    /// Counts every actual retained partial, including after encoding refusal.
    pub(in super::super) fn retained_storage_data_with_error<E: StorageError>(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        let Self {
            member,
            baseline,
            additions,
            wrapper,
            replacement,
            prepared: _,
            complete: _,
            wire: _,
        } = self;
        retained_values::sum_with_error::<E, _>(
            [
                member.retained_shared_storage_data().map_err(E::runtime)?,
                replacement.capacity(),
                baseline
                    .as_ref()
                    .map(|value| retained_values::value_storage_with_error::<E>(value, 0, maximum))
                    .transpose()?
                    .unwrap_or(0),
                additions
                    .as_ref()
                    .map(|value| retained_values::value_storage_with_error::<E>(value, 0, maximum))
                    .transpose()?
                    .unwrap_or(0),
                wrapper
                    .as_ref()
                    .map(|value| retained_values::value_storage_with_error::<E>(value, 0, maximum))
                    .transpose()?
                    .unwrap_or(0),
            ],
            maximum,
        )
    }

    pub(in super::super) fn construction_transient_data() -> usize {
        // Actual retaining initializer and its Option assignment precede the
        // Source field write; these are DATA temporaries, not heap R.
        std::mem::size_of::<Self>() + std::mem::size_of::<Option<Self>>()
    }

    /// Names actual state/member/cursor controls, excluding renderer work.
    pub(in super::super) fn wire_counter_scratch_data() -> usize {
        OriginalNativeImport18StartupMember::authentication_counter_scratch_data()
            + std::mem::size_of::<&Self>()
            + std::mem::size_of::<Option<&Self>>()
            + std::mem::size_of::<Result<&Self, RuntimeError>>()
            + std::mem::size_of::<Result<&Self, OperationFailure>>()
            + std::mem::size_of::<&Cell<Import18WireStage>>()
            // Expected, next and the actual Cell::get return are independent
            // literal cursor values at the defining advance call.
            + 3 * std::mem::size_of::<Import18WireStage>()
            + std::mem::size_of::<bool>()
            + std::mem::size_of::<Result<(), RuntimeError>>()
            + std::mem::size_of::<Result<(), OperationFailure>>()
    }

    pub(in super::super) fn begin_wire_data(&self) -> Result<(), RuntimeError> {
        if !self.complete || self.wire.get() != Import18WireStage::Unused {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.advance_wire_data(Import18WireStage::Unused, Import18WireStage::Retaining)
    }

    pub(in super::super) fn prepared_wire_data(&self) -> Result<(), RuntimeError> {
        self.advance_wire_data(Import18WireStage::Retaining, Import18WireStage::Prepared)
    }

    pub(in super::super) fn begin_publication_data(&self) -> Result<(), RuntimeError> {
        self.advance_wire_data(Import18WireStage::Prepared, Import18WireStage::Publishing)
    }

    pub(in super::super) fn authenticate_publication_data(&self) -> Result<(), RuntimeError> {
        if !self.complete || self.wire.get() != Import18WireStage::Publishing {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(in super::super) fn complete_publication_data(&self) -> Result<(), RuntimeError> {
        self.advance_wire_data(Import18WireStage::Publishing, Import18WireStage::Complete)
    }

    fn advance_wire_data(
        &self,
        expected: Import18WireStage,
        next: Import18WireStage,
    ) -> Result<(), RuntimeError> {
        advance_wire_stage(&self.wire, self.complete, expected, next)
    }
}

// This helper moves only the literal private-write cursor. The enclosing
// methods retain the real member and Source checks; a cursor is never a grant.
fn advance_wire_stage(
    stage: &Cell<Import18WireStage>,
    complete: bool,
    expected: Import18WireStage,
    next: Import18WireStage,
) -> Result<(), RuntimeError> {
    if !complete || stage.get() != expected {
        return Err(RuntimeError::OutstandingObligations);
    }
    stage.set(next);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_or_interrupted_private_wire_cursor_never_restarts() {
        let stage = Cell::new(Import18WireStage::Unused);
        assert!(
            advance_wire_stage(
                &stage,
                false,
                Import18WireStage::Unused,
                Import18WireStage::Retaining,
            )
            .is_err()
        );
        assert!(stage.get() == Import18WireStage::Unused);

        advance_wire_stage(
            &stage,
            true,
            Import18WireStage::Unused,
            Import18WireStage::Retaining,
        )
        .unwrap();
        assert!(
            advance_wire_stage(
                &stage,
                true,
                Import18WireStage::Unused,
                Import18WireStage::Retaining,
            )
            .is_err()
        );
        assert!(
            advance_wire_stage(
                &stage,
                true,
                Import18WireStage::Prepared,
                Import18WireStage::Publishing,
            )
            .is_err()
        );
        assert!(stage.get() == Import18WireStage::Retaining);
    }

    #[test]
    fn private_wire_progress_is_ordered_and_terminal_without_authority() {
        let stage = Cell::new(Import18WireStage::Unused);
        for (before, after) in [
            (Import18WireStage::Unused, Import18WireStage::Retaining),
            (Import18WireStage::Retaining, Import18WireStage::Prepared),
            (Import18WireStage::Prepared, Import18WireStage::Publishing),
            (Import18WireStage::Publishing, Import18WireStage::Complete),
        ] {
            advance_wire_stage(&stage, true, before, after).unwrap();
            assert!(stage.get() == after);
            assert!(advance_wire_stage(&stage, true, before, after).is_err());
        }
        assert!(
            advance_wire_stage(
                &stage,
                true,
                Import18WireStage::Prepared,
                Import18WireStage::Publishing,
            )
            .is_err()
        );
        assert!(stage.get() == Import18WireStage::Complete);
    }
}

#[path = "import18/geometry.rs"]
mod geometry;

impl OriginalNativeImport18Finalization {
    /// Records every actual prefix without requiring a completed native member.
    ///
    /// # Errors
    /// Refuses unsupported depth/layout, exhausted rows or unavailable backing.
    pub(in super::super) fn record_retained_capacity_data(
        &self,
        census: &mut crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            member,
            baseline,
            additions,
            wrapper,
            replacement,
            prepared,
            complete,
            wire,
        } = self;

        fn fixed_cell<T: Copy>(_: &Cell<T>) {}

        census.observe_inline_data(prepared);
        census.observe_inline_data(complete);
        fixed_cell(wire);
        member.record_retained_capacity_data(census)?;
        census.observe(replacement)?;
        for value in [baseline, additions, wrapper].into_iter().flatten() {
            retained_values::record_value_capacity_data_with_error::<RuntimeError>(
                value, 0, census,
            )?;
        }
        Ok(())
    }
}
