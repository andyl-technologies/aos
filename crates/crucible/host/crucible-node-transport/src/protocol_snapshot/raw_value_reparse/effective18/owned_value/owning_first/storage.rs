//! Quotes the actual owning input/root beside the unchanged first engine row.

use super::super::storage::{add, sum};
use super::*;

/// Stores only numeric demand beside the same privately owned selected input.
#[derive(Clone, Copy)]
pub(crate) struct NativeImport18OwningFirstConstructionData {
    pub(super) maximum: usize,
    pub(super) retained: usize,
    transient: usize,
    scratch: usize,
}

impl NativeImport18OwningFirstConstructionData {
    pub(super) fn quote_data(
        selection: &NativeImport18RawSelectionData,
        maximum: usize,
    ) -> Result<Self, ProviderError> {
        let raw = selection.retained_frame_data()?;
        let input = selection.value_data()?;
        let engine = NativeImport18OwnedValuePassConstructionData::quote_data(raw, input, maximum)?;
        let (engine_r, engine_t, engine_s) = engine.requested_storage_data();
        let backing = engine_r
            .checked_sub(size_of::<
                Option<NativeImport18OwnedValuePassAttemptData<'static>>,
            >())
            .ok_or_else(invalid)?;
        let source = selection
            .retained_requested_storage_data(maximum)?
            .checked_sub(size_of::<Option<NativeImport18RawSelectionData>>())
            .ok_or_else(invalid)?;
        let retained = sum(&[
            size_of::<Option<NativeImport18OwningFirstAttemptData>>(),
            source,
            backing,
        ])?;
        // This separately names the actual owning take/state initializer. The
        // shared engine's probe/child/push/tree T retains its defining quote;
        // old source backing supplies neither constructor window.
        let initializer = sum(&[
            size_of::<NativeImport18OwningFirstAttemptData>(),
            size_of::<Option<NativeImport18OwningFirstAttemptData>>(),
            size_of::<state::FirstPassStateData>() * 2,
            size_of::<Vec<Reparse>>(),
            size_of::<BTreeMap<usize, usize>>(),
            size_of::<NativeImport18RawSelectionData>(),
            size_of::<Option<NativeImport18RawSelectionData>>(),
        ])?;
        let transient = engine_t.max(initializer);
        let scratch = add(Self::counter_scratch_data(), engine_s)?;
        if sum(&[retained, transient, scratch])? > maximum {
            return Err(exhausted());
        }
        Ok(Self {
            maximum,
            retained,
            transient,
            scratch,
        })
    }

    pub(super) fn dominates_data(&self, current: &Self) -> bool {
        self.maximum == current.maximum
            && self.retained >= current.retained
            && self.transient >= current.transient
            && self.scratch >= current.scratch
    }

    #[cfg(test)]
    pub(super) fn shorten_axis_data(&mut self, axis: usize) {
        match axis {
            0 => self.retained -= 1,
            1 => self.transient -= 1,
            _ => self.scratch -= 1,
        }
    }

    /// Returns full owning R, independent first/outer T and actual fixed S.
    pub(crate) const fn requested_storage_data(&self) -> (usize, usize, usize) {
        (self.retained, self.transient, self.scratch)
    }

    /// Names actual owning, short-loan, shared-engine and observation controls.
    pub(crate) fn counter_scratch_data() -> usize {
        size_of::<Self>() * 2
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<&Self>() * 3
            + size_of::<Option<Self>>()
            + size_of::<NativeImport18OwningFirstAttemptData>()
            + size_of::<Option<NativeImport18OwningFirstAttemptData>>()
            + size_of::<&mut Option<NativeImport18OwningFirstAttemptData>>()
            + size_of::<&mut NativeImport18OwningFirstAttemptData>() * 2
            + size_of::<&NativeImport18OwningFirstAttemptData>() * 2
            + size_of::<NativeImport18RawSelectionData>()
            + size_of::<Option<NativeImport18RawSelectionData>>()
            + size_of::<&mut Option<NativeImport18RawSelectionData>>()
            + size_of::<&NativeImport18RawSelectionData>() * 3
            + size_of::<Result<&NativeImport18RawSelectionData, ProviderError>>()
            + size_of::<&RetainedFrame>()
            + size_of::<&Value>()
            + size_of::<Result<&Value, ProviderError>>()
            + size_of::<Result<&RetainedFrame, ProviderError>>()
            + size_of::<NativeImport18OwnedValuePassConstructionData<'static>>() * 2
            + size_of::<state::FirstPassStateData>() * 2
            + size_of::<&mut state::FirstPassStateData>()
            + size_of::<NativeImport18FirstFlatViewData<'static>>()
            + size_of::<Result<NativeImport18FirstFlatViewData<'static>, ProviderError>>()
            + size_of::<NativeImport18OwningFirstCensusData>()
            + size_of::<Stage>()
            + size_of::<Option<bool>>()
            + size_of::<[usize; 3]>() * 2
            + size_of::<[usize; 7]>()
            + size_of::<&[usize]>() * 3
            + size_of::<(usize, usize, usize)>()
            + size_of::<Result<(usize, usize, usize), ProviderError>>()
            + size_of::<Result<(), ProviderError>>() * 3
            + size_of::<Result<usize, ProviderError>>() * 3
            + size_of::<&Result<usize, ProviderError>>()
            + size_of::<usize>() * 10
            + state::FirstPassStateData::counter_scratch_data()
            + NativeImport18RawSelectionConstructionData::counter_scratch_data()
            // The nested borrowed quote runs before engine_s is returned. Its
            // entire static quote counter is a pre-admitted prerequisite here;
            // the returned engine row cannot fund its own quotation.
            + NativeImport18OwnedValuePassConstructionData::counter_scratch_data()
    }
}
