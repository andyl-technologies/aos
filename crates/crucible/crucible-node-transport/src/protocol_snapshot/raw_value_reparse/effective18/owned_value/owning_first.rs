//! Retains a checked immutable raw selection and the sole first-pass flat state.
//!
//! The attempt is entirely by value. Engine calls borrow its immutable selection
//! and mutate disjoint source-free state only for that call. Failed state stays
//! rooted without success-only allocation; completion lends the shared projection.

use super::*;

mod storage;
pub(crate) use storage::NativeImport18OwningFirstConstructionData;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Taking,
    Selected,
    Quoted,
    Complete,
    Failed,
}

/// Records actual current owning-first storage without renewing admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeImport18OwningFirstCensusData {
    /// Marks an installed owner before its actual observation finishes.
    Pending,
    /// Reports current root, input backing and all initialized flat histories.
    Observed {
        /// Counts actual capacities and pinned requested backing layouts.
        requested_bytes: usize,
        /// Compares with the same attempt's quoted R when present.
        within_row: Option<bool>,
    },
    /// Retains checked source/state observation refusal.
    Refused,
}

/// Owns one actual immutable selected input and one spent first-pass state.
///
/// This type has no source lifetime, self-reference, ordinary deep Value or
/// mutable recovery method. Completion does not enable an owned next-pass input.
pub(crate) struct NativeImport18OwningFirstAttemptData {
    stage: Stage,
    selection: Option<NativeImport18RawSelectionData>,
    row: Option<NativeImport18OwningFirstConstructionData>,
    state: state::FirstPassStateData,
    census: NativeImport18OwningFirstCensusData,
}

impl NativeImport18OwningFirstAttemptData {
    /// Names additional fixed take R/T/S before moving existing input custody.
    ///
    /// The selection's actual shared backing remains independently retained and
    /// charged while moving. No static prelude replaces that existing debt.
    /// Its fixed S includes the complete nested borrowed-quote counter; keep
    /// that pre-admitted workspace available through quote_into_data as well.
    pub(crate) fn take_requested_storage_data() -> (usize, usize, usize) {
        (
            size_of::<Option<Self>>(),
            size_of::<Self>()
                + size_of::<Option<Self>>()
                + size_of::<state::FirstPassStateData>() * 2
                + size_of::<Vec<Reparse>>()
                + size_of::<BTreeMap<usize, usize>>()
                + size_of::<NativeImport18RawSelectionData>()
                + size_of::<Option<NativeImport18RawSelectionData>>(),
            NativeImport18OwningFirstConstructionData::counter_scratch_data(),
        )
    }

    /// Roots the actual owning selection and empty state before fallible checks.
    ///
    /// # Errors
    /// Refuses reuse, missing/failed input or actual source census. The original
    /// selection and any already initialized state remain under the spent output.
    pub(crate) fn take_into_data(
        selection: &mut Option<NativeImport18RawSelectionData>,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(invalid());
        }
        *output = Some(Self {
            stage: Stage::Taking,
            selection: None,
            row: None,
            state: state::FirstPassStateData::new_data(),
            census: NativeImport18OwningFirstCensusData::Pending,
        });
        let owner = output.as_mut().ok_or_else(invalid)?;
        owner.selection = selection.take();
        let result = (|| {
            owner.selection.as_ref().ok_or_else(invalid)?.value_data()?;
            owner.stage = Stage::Selected;
            Ok(())
        })();
        owner.observe_result_data(result)
    }

    /// Stores this same privately owned input's actual prospective first row.
    ///
    /// The caller first admits the fixed S from take_requested_storage_data,
    /// including the nested engine quote counter, before this quotation. The
    /// returned complete R/T/S must then be admitted independently before
    /// run_data; it supplies no credit retroactively for its own quotation.
    /// The row grants no Source, normalization stage or native permission.
    ///
    /// # Errors
    /// Refuses reuse/state, original source/quote failures or the supplied bound.
    pub(crate) fn quote_into_data(&mut self, maximum: usize) -> Result<(), ProviderError> {
        if self.stage != Stage::Selected {
            return Err(invalid());
        }
        self.stage = Stage::Failed;
        let result = (|| {
            self.row = Some(NativeImport18OwningFirstConstructionData::quote_data(
                self.selection.as_ref().ok_or_else(invalid)?,
                maximum,
            )?);
            self.stage = Stage::Quoted;
            Ok(())
        })();
        self.observe_result_data(result)
    }

    /// Returns the same attempt's independently admitted first-pass R/T/S.
    ///
    /// # Errors
    /// Refuses missing/failed prospective state.
    pub(crate) fn requested_storage_data(&self) -> Result<(usize, usize, usize), ProviderError> {
        if self.stage != Stage::Quoted {
            return Err(invalid());
        }
        Ok(self
            .row
            .as_ref()
            .ok_or_else(invalid)?
            .requested_storage_data())
    }

    /// Runs the sole first normalizer once against this actual immutable input.
    ///
    /// The source and state are borrowed as disjoint fields only during this
    /// call. No temporary borrowed owner is retained or reconstructed afterward.
    ///
    /// # Errors
    /// Refuses reuse/state, changed/short quote, exact locked adapter/child failure
    /// or actual census. Original errors win; every partial state remains owned.
    pub(crate) fn run_data(&mut self) -> Result<(), ProviderError> {
        if self.stage != Stage::Quoted {
            return Err(invalid());
        }
        self.stage = Stage::Failed;
        let result = (|| {
            let Self {
                selection,
                row,
                state,
                ..
            } = self;
            let selection = selection.as_ref().ok_or_else(invalid)?;
            let row = row.as_ref().ok_or_else(invalid)?;
            let current =
                NativeImport18OwningFirstConstructionData::quote_data(selection, row.maximum)?;
            if !row.dominates_data(&current) {
                return Err(exhausted());
            }
            let raw = selection.retained_frame_data()?;
            let input = selection.value_data()?;
            let borrowed_row =
                NativeImport18OwnedValuePassConstructionData::quote_data(raw, input, row.maximum)?;
            state.run_data(input, &borrowed_row)
        })();
        self.observe_result_data(result)?;
        self.state.failed = false;
        self.state.complete = true;
        self.stage = Stage::Complete;
        Ok(())
    }

    /// Borrows the actual successful one-pass result without another adapter pass.
    ///
    /// # Errors
    /// Refuses failed/incomplete state or its missing immutable selected input.
    pub(crate) fn completed_data(
        &self,
    ) -> Result<NativeImport18FirstFlatViewData<'_>, ProviderError> {
        if self.stage != Stage::Complete || self.state.failed || !self.state.complete {
            return Err(invalid());
        }
        let input = self.selection.as_ref().ok_or_else(invalid)?.value_data()?;
        Ok(state_view::raw_data(&self.state, input))
    }

    pub(super) fn state_data(&self) -> &state::FirstPassStateData {
        &self.state
    }

    /// Borrows the retained original input even after a first-pass refusal.
    ///
    /// # Errors
    /// Refuses an attempt that never took a selection.
    pub(crate) fn retained_selection_data(
        &self,
    ) -> Result<&NativeImport18RawSelectionData, ProviderError> {
        self.selection.as_ref().ok_or_else(invalid)
    }

    /// Returns actual current depth including failed/overwritten flat children.
    pub(crate) const fn maximum_intermediate_depth_data(&self) -> usize {
        self.state.maximum_intermediate_depth
    }

    /// Returns the same installed owner's current observation snapshot.
    pub(crate) const fn census_data(&self) -> NativeImport18OwningFirstCensusData {
        self.census
    }

    /// Counts the actual root/input backing and every initialized flat child.
    ///
    /// # Errors
    /// Refuses actual source/state observation, checked layout or the bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        let Self {
            stage: _,
            selection,
            row: _,
            state,
            census: _,
        } = self;
        let source = match selection {
            Some(selection) => selection
                .retained_requested_storage_data(maximum)?
                .checked_sub(size_of::<Option<NativeImport18RawSelectionData>>())
                .ok_or_else(invalid)?,
            None => 0,
        };
        let retained = super::storage::sum(&[
            size_of::<Option<Self>>(),
            source,
            state.retained_backing_data(maximum)?,
        ])?;
        if retained > maximum {
            return Err(exhausted());
        }
        Ok(retained)
    }

    fn observe_result_data(
        &mut self,
        result: Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        let census = self.retained_requested_storage_data(usize::MAX);
        self.census = match &census {
            Ok(bytes) => NativeImport18OwningFirstCensusData::Observed {
                requested_bytes: *bytes,
                within_row: self.row.as_ref().map(|row| *bytes <= row.retained),
            },
            Err(_) => NativeImport18OwningFirstCensusData::Refused,
        };
        if result.is_err() {
            self.stage = Stage::Failed;
        }
        result?;
        let bytes = match census {
            Ok(bytes) => bytes,
            Err(error) => {
                self.stage = Stage::Failed;
                return Err(error);
            }
        };
        if self.row.as_ref().is_some_and(|row| bytes > row.retained) {
            self.stage = Stage::Failed;
            return Err(exhausted());
        }
        Ok(())
    }
}
