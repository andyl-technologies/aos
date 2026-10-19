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

mod input;
mod response_shape;
mod storage;
mod view;
mod walk;

pub(crate) use input::NativeImport18NextValueInputData;
pub(crate) use response_shape::{
    NativeImport18ResponseShapeCutsData, NativeImport18ResponseShapeCutsPreludeData,
    NativeImport18ResponseValueCutData, NativeImport18ResponseValueCutLocationData,
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
    failed: bool,
    complete: bool,
    mode: Option<RawMode>,
    reparses: Vec<Reparse>,
    lookup: BTreeMap<OwnedValueNodeIdentityData, usize>,
    maximum_intermediate_depth: usize,
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
            failed: true,
            complete: false,
            mode: None,
            reparses: Vec::new(),
            lookup: BTreeMap::new(),
            maximum_intermediate_depth: 0,
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
        owner.failed = false;
        owner.complete = true;
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
        self.reparses
            .try_reserve_exact(row.reparses)
            .map_err(|_| exhausted())?;
        if self.reparses.capacity() > row.reparses {
            return Err(exhausted());
        }
        // This is the actual fixed probe result retained by this same completed
        // preceding owner, not a caller Boolean or a second feature assumption.
        self.mode = input.selected.loans.first.state.mode;
        let mut source = walk::Walk::new_data(input, row.prewalk.population)?;
        while let Some((value, depth)) = source.next_data()? {
            self.maximum_intermediate_depth = self.maximum_intermediate_depth.max(depth);
            let SourceKind::Object(mut fields) = value.kind_data()? else {
                continue;
            };
            if !matches!(self.mode, Some(RawMode::Reparse)) {
                continue;
            }
            let Some((key, payload)) = fields.next() else {
                continue;
            };
            if key != RAW_VALUE_KEY {
                continue;
            }
            let SourceKind::String(payload) = payload.kind_data()? else {
                return Err(invalid());
            };
            let position = self.reparses.len();
            if position >= row.reparses {
                return Err(exhausted());
            }
            let identity = value.identity_data()?;
            self.reparses.push(Reparse {
                source: identity,
                attempt: None,
            });
            if self.lookup.insert(identity, position).is_some() {
                return Err(invalid());
            }
            let child = self.reparses.get_mut(position).ok_or_else(invalid)?;
            let child_row =
                NativeImport18EffectiveTextConstructionData::quote_data(payload, row.maximum)?;
            NativeImport18EffectiveTextAttemptData::read_into_data(
                payload,
                &child_row,
                &mut child.attempt,
            )?;
            let child = child.attempt.as_ref().ok_or_else(invalid)?;
            self.maximum_intermediate_depth = self.maximum_intermediate_depth.max(add(
                depth.checked_sub(1).ok_or_else(invalid)?,
                child.maximum_intermediate_depth_data(),
            )?);
            // Locked MapDeserializer diagnoses remaining fields only after the
            // Raw String parser returns. Keep that actual child even on refusal.
            if fields.next().is_some() {
                return Err(invalid());
            }
            source.skip_children_data();
        }
        Ok(())
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
        if self.failed || !self.complete {
            return Err(invalid());
        }
        Ok(view::prior_data(self, input.selected))
    }

    /// Returns actual prior and newly created flat-child intermediate depth.
    pub(crate) const fn maximum_intermediate_depth_data(&self) -> usize {
        self.maximum_intermediate_depth
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
        let Self {
            row: _,
            failed: _,
            complete: _,
            mode: _,
            reparses,
            lookup,
            maximum_intermediate_depth: _,
            census: _,
        } = self;
        let mut retained = sum(&[
            size_of::<Option<Self>>(),
            mul(reparses.capacity(), size_of::<Reparse>())?,
            tree_storage_data(
                usize::from(!lookup.is_empty()),
                lookup.len(),
                size_of::<(OwnedValueNodeIdentityData, usize)>(),
                align_of::<OwnedValueNodeIdentityData>(),
            )?,
        ])?;
        for Reparse { source: _, attempt } in reparses {
            if let Some(attempt) = attempt {
                retained = add(
                    retained,
                    attempt
                        .retained_requested_storage_data(maximum)?
                        .checked_sub(size_of::<Option<NativeImport18EffectiveTextAttemptData>>())
                        .ok_or_else(invalid)?,
                )?;
            }
        }
        if retained > maximum {
            return Err(exhausted());
        }
        Ok(retained)
    }
}
