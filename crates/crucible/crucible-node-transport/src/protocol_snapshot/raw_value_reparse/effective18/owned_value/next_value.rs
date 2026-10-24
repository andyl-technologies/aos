//! Executes one actual owned-Value adapter pass over one completed prior view.
//!
//! A same-owner private input binds the selected raw/flat node. Only actual
//! first-key Raw strings create new flat text attempts; their output is never
//! fed through another pass. Every failed child and overwritten text history
//! remains rooted before the remaining-key check. There is no ordinary Value
//! output, native grant or input accepting this pass's own output.

use super::storage::{add, mul, sum};
use super::*;
use crate::retained_metadata::requested_storage::tree_storage_data;
use input::{
    BoundaryIdentity, NodeIdentity as OwnedValueNodeIdentityData, SourceArray, SourceKind,
    SourceObject, SourceView,
};

mod engine;
mod first_bank;
mod input;
pub(crate) use first_bank::{
    NativeImport18FirstBankCensusData, NativeImport18FirstBankConstructionData,
    NativeImport18FirstBankCustodyData, NativeImport18FirstBankData, NativeImport18FirstChildData,
    NativeImport18FirstSelectionConstructionData, NativeImport18FirstSelectionData,
};
mod owning;
pub(crate) use owning::{NativeImport18OwningNextAttemptData, NativeImport18OwningNextCensusData};
pub(super) mod response_shape;
mod storage;
mod view;
mod walk;

pub(crate) use input::NativeImport18NextValueInputData;
pub(crate) use response_shape::owning::{
    NativeImport18OwningResponseActionData, NativeImport18OwningResponseAttemptData,
    NativeImport18OwningResponseCensusData,
};
pub(crate) use response_shape::{
    NativeImport18ResponseShapeCutsData, NativeImport18ResponseShapeCutsPreludeData,
    NativeImport18ResponseValueCutData, NativeImport18ResponseValueCutLocationData,
    NativeImport18ShapeValidateAttemptData, NativeImport18ShapeValidateCensusData,
};
pub(crate) use storage::{
    NativeImport18NextValuePassConstructionData, NativeImport18NextValuePrewalkData,
};
pub(crate) use view::{
    NativeImport18NextValuePassArrayData, NativeImport18NextValuePassKindData,
    NativeImport18NextValuePassObjectData, NativeImport18NextValuePassViewData,
};

struct Reparse {
    source: OwnedValueNodeIdentityData,
    attempt: Option<NativeImport18EffectiveTextAttemptData>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

/// Reports actual completed or failed next-pass retained storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeImport18NextValueCensusData {
    /// Marks an installed output before its final same-owner observation.
    Pending,
    /// Records actual capacity and comparison against this same row's R.
    Observed {
        /// Counts actual root, spare child slots, lookup nodes and flat children.
        requested_bytes: usize,
        /// Compares that observation against this exact independently quoted R.
        within_row: bool,
    },
    /// Retains refusal to finish checked actual counting.
    Refused,
}

/// Retains one spent next-pass attempt and all actual flat child prefixes.
///
/// The prior bank is independently retained by the caller. Resource addresses
/// in this owner are compared only, never dereferenced, serialized or granted.
pub(crate) struct NativeImport18NextValuePassAttemptData<'bank> {
    row: NativeImport18NextValuePassConstructionData<'bank>,
    state: engine::NextPassStateData,
    census: NativeImport18NextValueCensusData,
}

impl<'bank> NativeImport18NextValuePassAttemptData<'bank> {
    /// Installs spent failure custody before row recheck or any allocation.
    ///
    /// The complete returned R/T/S must be independently admitted beside the
    /// same prior/raw/source owners. Every installed result is actually censused
    /// before return; an earlier construction error is preserved unchanged.
    ///
    /// # Errors
    /// Refuses reuse, foreign input/row, storage, exact Raw semantics or checked
    /// census. Initialized flat children and spare capacity are never cleared.
    pub(crate) fn read_into_data(
        input: NativeImport18NextValueInputData<'bank>,
        row: &NativeImport18NextValuePassConstructionData<'bank>,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(invalid());
        }
        *output = Some(Self {
            row: *row,
            state: engine::NextPassStateData::new_data(),
            census: NativeImport18NextValueCensusData::Pending,
        });
        let owner = output.as_mut().ok_or_else(invalid)?;
        let result = owner.construct_data(input, row);
        let census = owner.retained_requested_storage_data(usize::MAX);
        owner.census = match &census {
            Ok(requested_bytes) => NativeImport18NextValueCensusData::Observed {
                requested_bytes: *requested_bytes,
                within_row: *requested_bytes <= row.retained,
            },
            Err(_) => NativeImport18NextValueCensusData::Refused,
        };
        result?;
        if census? > row.retained {
            return Err(exhausted());
        }
        owner.state.failed = false;
        owner.state.complete = true;
        Ok(())
    }

    fn construct_data(
        &mut self,
        input: NativeImport18NextValueInputData<'bank>,
        row: &NativeImport18NextValuePassConstructionData<'bank>,
    ) -> Result<(), ProviderError> {
        row.prewalk.authenticate_data(input)?;
        let current = NativeImport18NextValuePassConstructionData::quote_data(
            input,
            &row.prewalk,
            row.maximum,
        )?;
        if !row.dominates_data(&current) {
            return Err(exhausted());
        }
        self.state.run_data(input, row)
    }

    /// Borrows the exact one-next-pass result without performing another pass.
    ///
    /// # Errors
    /// Refuses a foreign selected node/owner or a failed/incomplete attempt.
    pub(crate) fn completed_data<'a>(
        &'a self,
        input: NativeImport18NextValueInputData<'a>,
    ) -> Result<NativeImport18NextValuePassViewData<'a>, ProviderError> {
        self.row.prewalk.authenticate_data(input)?;
        if self.state.failed || !self.state.complete {
            return Err(invalid());
        }
        Ok(view::prior_data(&self.state, input.selected))
    }

    /// Returns actual prior and newly created flat-child intermediate depth.
    pub(crate) const fn maximum_intermediate_depth_data(&self) -> usize {
        self.state.maximum_intermediate_depth
    }

    /// Returns the same owner's post-attempt actual retained observation.
    pub(crate) const fn census_data(&self) -> NativeImport18NextValueCensusData {
        self.census
    }

    /// Counts actual spare child slots, lookup nodes and every flat failed child.
    ///
    /// # Errors
    /// Refuses checked layout overflow or actual demand above the supplied bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        let retained = add(
            size_of::<Option<Self>>(),
            self.state.retained_backing_data(maximum)?,
        )?;
        if retained > maximum {
            return Err(exhausted());
        }
        Ok(retained)
    }
}
