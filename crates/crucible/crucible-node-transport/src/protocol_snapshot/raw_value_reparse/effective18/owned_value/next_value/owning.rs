//! Owns checked immutable FIRST input and the sole next-pass mutable flat state.
//!
//! Numeric rows describe demand only. Real short-lived input loans and engine
//! rows are reconstructed from this same private selection at every stage.
//! Prewalk workspace is admitted before quote allocates its iterator spine;
//! full next demand is admitted before run. No sibling loan is stored.

use super::*;
use first_bank::NativeImport18FirstSelectionConstructionData;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Taking,
    Selected,
    Prewalk,
    Quoted,
    Complete,
    Failed,
}

#[derive(Clone, Copy)]
struct PrewalkPlan {
    maximum: usize,
    population: usize,
    transient: usize,
    scratch: usize,
}

#[derive(Clone, Copy)]
struct Plan {
    maximum: usize,
    retained: usize,
    transient: usize,
    scratch: usize,
    reparses: usize,
}

/// Reports actual current input and all next-pass partial histories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeImport18OwningNextCensusData {
    /// Marks rooted custody before observation.
    Pending,
    /// Carries actual storage and comparison when a full row exists.
    Observed {
        /// Counts the current actual root and every retained backing allocation.
        requested_bytes: usize,
        /// Compares with this same attempt's full row when one exists.
        within_row: Option<bool>,
    },
    /// Records actual source/flat observation refusal.
    Refused,
}

/// Owns one first-to-second attempt and its immutable preceding boundary.
///
/// This type has no source lifetime, mutable recovery, ordinary deep Value,
/// next-output input constructor, Serialize or operational Source permission.
pub(crate) struct NativeImport18OwningNextAttemptData {
    stage: Stage,
    selection: Option<NativeImport18FirstSelectionData>,
    prewalk: Option<PrewalkPlan>,
    row: Option<Plan>,
    state: engine::NextPassStateData,
    census: NativeImport18OwningNextCensusData,
}

impl NativeImport18OwningNextAttemptData {
    /// Names fixed additional transfer demand before taking an existing selection.
    ///
    /// Existing input backing remains charged separately; fixed S includes all
    /// static prewalk/quote prerequisites and stays admitted through quotation.
    pub(crate) fn take_requested_storage_data() -> (usize, usize, usize) {
        (
            size_of::<Option<Self>>(),
            initializer_data(),
            counter_data(),
        )
    }

    /// Roots the original owning selection and empty state before fallible checks.
    ///
    /// # Errors
    /// Refuses reuse, failed/missing input or actual census. Every moved input
    /// stays rooted under the installed attempt, including all FIRST histories.
    pub(crate) fn take_into_data(
        selection: &mut Option<NativeImport18FirstSelectionData>,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(invalid());
        }
        *output = Some(Self {
            stage: Stage::Taking,
            selection: None,
            prewalk: None,
            row: None,
            state: engine::NextPassStateData::new_data(),
            census: NativeImport18OwningNextCensusData::Pending,
        });
        let owner = output.as_mut().ok_or_else(invalid)?;
        owner.selection = selection.take();
        let result = (|| {
            owner.selection.as_ref().ok_or_else(invalid)?.input_data()?;
            owner.stage = Stage::Selected;
            Ok(())
        })();
        owner.observe_result_data(result)
    }

    /// Quotes actual bounded populations before any logical-spine allocation.
    ///
    /// Admit fixed take S before entry. Then admit this returned R/T/S beside
    /// actual parent custody before quote_into_data allocates a borrowed spine.
    ///
    /// # Errors
    /// Refuses reuse, actual source, layout overflow or the supplied bound.
    pub(crate) fn prewalk_into_data(&mut self, maximum: usize) -> Result<(), ProviderError> {
        if self.stage != Stage::Selected {
            return Err(invalid());
        }
        self.stage = Stage::Failed;
        let result = (|| {
            let input = self.selection.as_ref().ok_or_else(invalid)?.input_data()?;
            let prewalk = NativeImport18NextValuePrewalkData::quote_data(input, maximum)?;
            let (_, transient, scratch) = prewalk.requested_storage_data();
            let plan = PrewalkPlan {
                maximum,
                population: prewalk.population,
                transient,
                scratch: add(counter_data(), scratch)?,
            };
            let retained = self.retained_requested_storage_data(maximum)?;
            if sum(&[retained, plan.transient, plan.scratch])? > maximum {
                return Err(exhausted());
            }
            self.prewalk = Some(plan);
            self.stage = Stage::Prewalk;
            Ok(())
        })();
        self.observe_result_data(result)
    }

    /// Returns actual prior custody and prospective quote-spine workspace.
    ///
    /// # Errors
    /// Refuses missing or failed prewalk qualification.
    pub(crate) fn prewalk_requested_storage_data(
        &self,
    ) -> Result<(usize, usize, usize), ProviderError> {
        if self.stage != Stage::Prewalk {
            return Err(invalid());
        }
        let prewalk = self.prewalk.as_ref().ok_or_else(invalid)?;
        Ok((
            self.retained_requested_storage_data(prewalk.maximum)?,
            prewalk.transient,
            prewalk.scratch,
        ))
    }

    /// Quotes this actual immutable prior view after its prewalk row is admitted.
    ///
    /// # Errors
    /// Refuses reuse, changed/short prewalk, actual source, reserve or full bound.
    /// The input and unchanged empty/partial next state remain owned on failure.
    pub(crate) fn quote_into_data(&mut self) -> Result<(), ProviderError> {
        if self.stage != Stage::Prewalk {
            return Err(invalid());
        }
        self.stage = Stage::Failed;
        let result = (|| {
            let selected = self.selection.as_ref().ok_or_else(invalid)?;
            let prewalk = self.prewalk.as_ref().ok_or_else(invalid)?;
            let (row, _, _) = quote_data(selected, prewalk)?;
            self.row = Some(row);
            self.stage = Stage::Quoted;
            Ok(())
        })();
        self.observe_result_data(result)
    }

    /// Returns the complete same-owner row for independent execution admission.
    ///
    /// # Errors
    /// Refuses missing or failed full quotation.
    pub(crate) fn requested_storage_data(&self) -> Result<(usize, usize, usize), ProviderError> {
        if self.stage != Stage::Quoted {
            return Err(invalid());
        }
        let row = self.row.as_ref().ok_or_else(invalid)?;
        Ok((row.retained, row.transient, row.scratch))
    }

    /// Calls the sole next engine once with short immutable source loans.
    ///
    /// # Errors
    /// Refuses reuse, short actual row, reserve, exact locked semantic/parse error
    /// or census. Original errors win; failed and overwritten children stay owned.
    pub(crate) fn run_data(&mut self) -> Result<(), ProviderError> {
        if self.stage != Stage::Quoted {
            return Err(invalid());
        }
        self.stage = Stage::Failed;
        let result = (|| {
            let Self {
                selection,
                prewalk,
                row,
                state,
                ..
            } = self;
            let selected = selection.as_ref().ok_or_else(invalid)?;
            let prewalk = prewalk.as_ref().ok_or_else(invalid)?;
            let row = row.as_ref().ok_or_else(invalid)?;
            let (current, input, borrowed_row) = quote_data(selected, prewalk)?;
            if row.maximum != current.maximum
                || row.retained < current.retained
                || row.transient < current.transient
                || row.scratch < current.scratch
                || row.reparses < current.reparses
            {
                return Err(exhausted());
            }
            state.run_data(input, &borrowed_row)
        })();
        self.observe_result_data(result)?;
        self.state.failed = false;
        self.state.complete = true;
        self.stage = Stage::Complete;
        Ok(())
    }

    /// Borrows the actual second-pass projection without a third pass.
    ///
    /// # Errors
    /// Refuses failed/incomplete state or missing immutable input.
    pub(crate) fn completed_data(
        &self,
    ) -> Result<NativeImport18NextValuePassViewData<'_>, ProviderError> {
        if self.stage != Stage::Complete || self.state.failed || !self.state.complete {
            return Err(invalid());
        }
        let input = self.selection.as_ref().ok_or_else(invalid)?.input_data()?;
        Ok(view::prior_data(&self.state, input.selected))
    }

    /// Lends actual retained input after success or refusal without mutable access.
    ///
    /// # Errors
    /// Refuses a take that never received input.
    pub(crate) fn retained_selection_data(
        &self,
    ) -> Result<&NativeImport18FirstSelectionData, ProviderError> {
        self.selection.as_ref().ok_or_else(invalid)
    }

    /// Returns actual maximum depth including all failed flat child prefixes.
    pub(crate) const fn maximum_intermediate_depth_data(&self) -> usize {
        self.state.maximum_intermediate_depth
    }

    /// Returns the current observation snapshot without renewing credit.
    pub(crate) const fn census_data(&self) -> NativeImport18OwningNextCensusData {
        self.census
    }

    /// Counts actual root, immutable FIRST and all initialized next flat histories.
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
            prewalk: _,
            row: _,
            state,
            census: _,
        } = self;
        let prior = match selection {
            Some(value) => value
                .retained_requested_storage_data(maximum)?
                .checked_sub(size_of::<Option<NativeImport18FirstSelectionData>>())
                .ok_or_else(invalid)?,
            None => 0,
        };
        let retained = sum(&[
            size_of::<Option<Self>>(),
            prior,
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
            Ok(bytes) => NativeImport18OwningNextCensusData::Observed {
                requested_bytes: *bytes,
                within_row: self.row.as_ref().map(|row| *bytes <= row.retained),
            },
            Err(_) => NativeImport18OwningNextCensusData::Refused,
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

fn checked_prewalk_data<'a>(
    input: NativeImport18NextValueInputData<'a>,
    plan: &PrewalkPlan,
) -> Result<NativeImport18NextValuePrewalkData<'a>, ProviderError> {
    let current = NativeImport18NextValuePrewalkData::quote_data(input, plan.maximum)?;
    let (_, transient, scratch) = current.requested_storage_data();
    if current.population > plan.population
        || transient > plan.transient
        || add(counter_data(), scratch)? > plan.scratch
    {
        return Err(exhausted());
    }
    Ok(current)
}

fn quote_data<'a>(
    selected: &'a NativeImport18FirstSelectionData,
    plan: &PrewalkPlan,
) -> Result<
    (
        Plan,
        NativeImport18NextValueInputData<'a>,
        NativeImport18NextValuePassConstructionData<'a>,
    ),
    ProviderError,
> {
    let input = selected.input_data()?;
    let prewalk = checked_prewalk_data(input, plan)?;
    // Only after the independent prewalk check does logical quote reserve.
    let engine =
        NativeImport18NextValuePassConstructionData::quote_data(input, &prewalk, plan.maximum)?;
    let (r, t, s) = engine.requested_storage_data();
    let flat = r
        .checked_sub(size_of::<
            Option<NativeImport18NextValuePassAttemptData<'static>>,
        >())
        .ok_or_else(invalid)?;
    let prior = selected
        .retained_requested_storage_data(plan.maximum)?
        .checked_sub(size_of::<Option<NativeImport18FirstSelectionData>>())
        .ok_or_else(invalid)?;
    let retained = sum(&[
        size_of::<Option<NativeImport18OwningNextAttemptData>>(),
        prior,
        flat,
    ])?;
    let transient = t.max(initializer_data());
    let scratch = add(counter_data(), s)?;
    if sum(&[retained, transient, scratch])? > plan.maximum {
        return Err(exhausted());
    }
    Ok((
        Plan {
            maximum: plan.maximum,
            retained,
            transient,
            scratch,
            reparses: engine.reparses,
        },
        input,
        engine,
    ))
}

fn initializer_data() -> usize {
    size_of::<NativeImport18OwningNextAttemptData>()
        + size_of::<Option<NativeImport18OwningNextAttemptData>>()
        + size_of::<engine::NextPassStateData>() * 2
        + size_of::<Vec<Reparse>>()
        + size_of::<BTreeMap<OwnedValueNodeIdentityData, usize>>()
        + size_of::<NativeImport18FirstSelectionData>()
        + size_of::<Option<NativeImport18FirstSelectionData>>()
}

fn counter_data() -> usize {
    size_of::<NativeImport18OwningNextAttemptData>()
        + size_of::<Option<NativeImport18OwningNextAttemptData>>()
        + size_of::<&mut Option<NativeImport18OwningNextAttemptData>>()
        + size_of::<&mut NativeImport18OwningNextAttemptData>() * 2
        + size_of::<&NativeImport18OwningNextAttemptData>() * 2
        + size_of::<NativeImport18FirstSelectionData>()
        + size_of::<Option<NativeImport18FirstSelectionData>>()
        + size_of::<&mut Option<NativeImport18FirstSelectionData>>()
        + size_of::<&NativeImport18FirstSelectionData>() * 3
        + size_of::<Result<&NativeImport18FirstSelectionData, ProviderError>>()
        + size_of::<PrewalkPlan>() * 2
        + size_of::<Option<PrewalkPlan>>()
        + size_of::<&PrewalkPlan>() * 3
        + size_of::<(
            Plan,
            NativeImport18NextValueInputData<'static>,
            NativeImport18NextValuePassConstructionData<'static>,
        )>()
        + size_of::<
            Result<
                (
                    Plan,
                    NativeImport18NextValueInputData<'static>,
                    NativeImport18NextValuePassConstructionData<'static>,
                ),
                ProviderError,
            >,
        >()
        + size_of::<Plan>() * 2
        + size_of::<Result<Plan, ProviderError>>()
        + size_of::<Option<Plan>>()
        + size_of::<&Plan>() * 3
        + size_of::<engine::NextPassStateData>() * 2
        + size_of::<&mut engine::NextPassStateData>()
        + size_of::<NativeImport18NextValueInputData<'static>>() * 2
        + size_of::<NativeImport18NextValuePrewalkData<'static>>() * 2
        + size_of::<NativeImport18NextValuePassConstructionData<'static>>() * 2
        + size_of::<NativeImport18NextValuePassViewData<'static>>()
        + size_of::<Result<NativeImport18NextValuePassViewData<'static>, ProviderError>>()
        + size_of::<NativeImport18OwningNextCensusData>()
        + size_of::<Stage>()
        + size_of::<Option<bool>>()
        + size_of::<Result<(), ProviderError>>() * 3
        + size_of::<Result<usize, ProviderError>>() * 3
        + size_of::<&Result<usize, ProviderError>>()
        // Prewalk total, quote retained, quote total and actual census operands.
        + size_of::<[usize; 3]>() * 4
        + size_of::<&[usize]>() * 3
        + size_of::<(usize, usize, usize)>()
        + size_of::<Result<(usize, usize, usize), ProviderError>>()
        + size_of::<usize>() * 12
        + NativeImport18NextValuePassConstructionData::counter_scratch_data()
        + NativeImport18FirstSelectionConstructionData::counter_scratch_data()
}
