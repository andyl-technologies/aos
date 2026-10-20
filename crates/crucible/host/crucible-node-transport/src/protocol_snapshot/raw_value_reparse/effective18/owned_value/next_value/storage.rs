//! Quotes actual prior-node traversal and exactly one next flat adapter pass.

use super::*;

/// Binds an independently admitted borrowed prewalk to actual prior populations.
///
/// The retained source loan binds raw bytes, decoded nodes, preceding completed
/// owners and flat child banks for every row/output use. Addresses remain only
/// membership checks, never substitutes for immutable content custody.
#[derive(Clone, Copy)]
pub(crate) struct NativeImport18NextValuePrewalkData<'bank> {
    pub(super) raw: &'bank RetainedFrame,
    pub(super) first: input::FirstSource<'bank>,
    pub(super) prior: BoundaryIdentity,
    selected: OwnedValueNodeIdentityData,
    // Keep the actual source and every preceding bank immutable, not just its key.
    source: NativeImport18NextValueInputData<'bank>,
    pub(super) population: usize,
    maximum: usize,
    transient: usize,
    scratch: usize,
}

impl<'bank> NativeImport18NextValuePrewalkData<'bank> {
    /// Quotes actual prior physical nodes without allocating or parsing.
    ///
    /// Admit the defining static counter before this quote, then independently
    /// admit its returned borrowed-workspace T/S before quote_data traverses the
    /// arbitrary-depth logical view. No stored capacity or policy cap is demand.
    ///
    /// # Errors
    /// Refuses foreign/incomplete input, raw64, checked overflow or the bound.
    pub(crate) fn quote_data(
        input: NativeImport18NextValueInputData<'bank>,
        maximum: usize,
    ) -> Result<Self, ProviderError> {
        input.selected.loans.validate_data()?;
        input.selected.kind_data()?;
        let population = input.physical_population_data()?;
        let transient = sum(&[
            walk::workspace_data(population)?,
            size_of::<walk::Walk<'static>>() * 2,
            size_of::<Vec<walk::Frame<'static>>>() * 2,
        ])?;
        let scratch = NativeImport18NextValuePassConstructionData::counter_scratch_data();
        if add(transient, scratch)? > maximum {
            return Err(exhausted());
        }
        Ok(Self {
            raw: input.selected.loans.raw,
            first: input.selected.loans.first,
            prior: input.selected.loans.prior_data(),
            selected: input.key_data()?,
            source: input,
            population,
            maximum,
            transient,
            scratch,
        })
    }

    /// Returns the separately admitted quote workspace and fixed controls.
    pub(crate) const fn requested_storage_data(&self) -> (usize, usize, usize) {
        (0, self.transient, self.scratch)
    }

    pub(super) fn authenticate_data(
        &self,
        input: NativeImport18NextValueInputData<'_>,
    ) -> Result<(), ProviderError> {
        if !std::ptr::eq(self.raw, input.selected.loans.raw)
            || !self.first.same_data(input.selected.loans.first)
            || self.prior != input.selected.loans.prior_data()
            || self.selected != input.key_data()?
        {
            return Err(invalid());
        }
        self.source.selected.loans.validate_data()?;
        if self.source.key_data()? != self.selected {
            return Err(invalid());
        }
        input.selected.loans.validate_data()?;
        input.selected.kind_data()?;
        // Check actual population before any borrowed Vec reserve, including
        // before construction's re-quotation. Address equality alone funds no
        // larger replacement raw tree or enlarged actual flat bank.
        if input.physical_population_data()? > self.population {
            return Err(exhausted());
        }
        Ok(())
    }
}

/// Quotes one next-pass owner, flat children and independent constructor axes.
#[derive(Clone, Copy)]
pub(crate) struct NativeImport18NextValuePassConstructionData<'bank> {
    pub(super) prewalk: NativeImport18NextValuePrewalkData<'bank>,
    pub(super) maximum: usize,
    pub(super) reparses: usize,
    pub(super) retained: usize,
    transient: usize,
    scratch: usize,
}

impl<'bank> NativeImport18NextValuePassConstructionData<'bank> {
    /// Quotes actual potential first-key strings in one completed prior view.
    ///
    /// The exact prewalk's returned T/S must already be independently admitted.
    /// Quotation allocates only its explicitly priced borrowed iterator spine;
    /// it constructs no user Value, text child, next owner or protocol grant.
    /// It visits actual final prior children while all prior overwritten/failed
    /// text storage remains in its independently charged owning banks.
    ///
    /// # Errors
    /// Refuses changed prewalk/input, overflow, actual view inconsistency, reserve
    /// failure or requested axes beyond the same unchanged caller maximum.
    pub(crate) fn quote_data(
        input: NativeImport18NextValueInputData<'bank>,
        prewalk: &NativeImport18NextValuePrewalkData<'bank>,
        maximum: usize,
    ) -> Result<Self, ProviderError> {
        prewalk.authenticate_data(input)?;
        if maximum != prewalk.maximum {
            return Err(invalid());
        }
        let mut reparses = 0;
        let mut child_retained = 0;
        let mut child_transient = 0;
        let mut child_scratch = 0;
        let mut source = walk::Walk::new_data(input, prewalk.population)?;
        while let Some((value, _)) = source.next_data()? {
            let SourceKind::Object(mut fields) = value.kind_data()? else {
                continue;
            };
            let Some((key, payload)) = fields.next() else {
                continue;
            };
            if key != RAW_VALUE_KEY {
                continue;
            }
            let SourceKind::String(payload) = payload.kind_data()? else {
                continue;
            };
            let row = NativeImport18EffectiveTextConstructionData::quote_data(payload, maximum)?;
            reparses = add(reparses, 1)?;
            child_retained = add(
                child_retained,
                row.retained_requested_bytes_data()
                    .checked_sub(size_of::<Option<NativeImport18EffectiveTextAttemptData>>())
                    .ok_or_else(invalid)?,
            )?;
            child_transient = child_transient.max(row.transient_requested_bytes_data());
            child_scratch = child_scratch.max(row.declared_counter_scratch_data());
        }
        let trees = tree_storage_data(
            reparses,
            reparses,
            size_of::<(OwnedValueNodeIdentityData, usize)>(),
            align_of::<OwnedValueNodeIdentityData>(),
        )?;
        let retained = sum(&[
            size_of::<Option<NativeImport18NextValuePassAttemptData<'static>>>(),
            mul(reparses, size_of::<Reparse>())?,
            child_retained,
            trees,
        ])?;
        let initializer = sum(&[
            size_of::<engine::NextPassStateData>() * 2,
            size_of::<NativeImport18NextValuePassAttemptData<'static>>(),
            size_of::<Option<NativeImport18NextValuePassAttemptData<'static>>>(),
            size_of::<Vec<Reparse>>(),
            size_of::<BTreeMap<OwnedValueNodeIdentityData, usize>>(),
        ])?;
        let child_push = sum(&[
            size_of::<Reparse>() * 2,
            size_of::<Option<NativeImport18EffectiveTextAttemptData>>(),
        ])?;
        // The borrowed spine stays live during child construction and tree
        // insertion. Its backing therefore SUMS with those transient windows;
        // old retained children and lookup backing fund neither operation.
        let transient = add(
            prewalk.transient,
            initializer.max(child_push).max(child_transient).max(trees),
        )?;
        let scratch = add(Self::counter_scratch_data(), child_scratch)?;
        if sum(&[retained, transient, scratch])? > maximum {
            return Err(exhausted());
        }
        Ok(Self {
            prewalk: *prewalk,
            maximum,
            reparses,
            retained,
            transient,
            scratch,
        })
    }

    pub(super) fn dominates_data(&self, current: &Self) -> bool {
        std::ptr::eq(self.prewalk.raw, current.prewalk.raw)
            && self.prewalk.first.same_data(current.prewalk.first)
            && self.prewalk.prior == current.prewalk.prior
            && self.prewalk.selected == current.prewalk.selected
            && self.prewalk.population >= current.prewalk.population
            && self.maximum == current.maximum
            && self.reparses >= current.reparses
            && self.retained >= current.retained
            && self.transient >= current.transient
            && self.scratch >= current.scratch
    }

    /// Returns independently admitted next-pass R, simultaneous T and fixed S.
    pub(crate) const fn requested_storage_data(&self) -> (usize, usize, usize) {
        (self.retained, self.transient, self.scratch)
    }

    /// Names input, quote/read/census, actual lookup and return controls.
    pub(crate) fn counter_scratch_data() -> usize {
        use std::collections::btree_map::{Entry, OccupiedEntry, VacantEntry};
        // Authentication independently copies the retained source loan and
        // selected view before deriving its key. Name those new live controls.
        let source_recheck = size_of::<NativeImport18NextValueInputData<'static>>()
            + size_of::<SourceView<'static>>()
            + size_of::<&NativeImport18NextValuePrewalkData<'static>>()
            + size_of::<Result<OwnedValueNodeIdentityData, ProviderError>>();
        let rows = size_of::<Self>() * 2
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<NativeImport18NextValuePrewalkData<'static>>() * 2
            + size_of::<Result<NativeImport18NextValuePrewalkData<'static>, ProviderError>>()
            + size_of::<&Self>() * 3
            + size_of::<&NativeImport18NextValuePrewalkData<'static>>() * 3
            + size_of::<NativeImport18NextValueInputData<'static>>() * 3
            + size_of::<Result<NativeImport18NextValueInputData<'static>, ProviderError>>()
            + size_of::<OwnedValueNodeIdentityData>() * 3
            + size_of::<Option<RawMode>>()
            + size_of::<&RetainedFrame>() * 3
            + size_of::<&NativeImport18OwnedValuePassAttemptData<'static>>() * 3;
        let outputs = size_of::<NativeImport18NextValuePassAttemptData<'static>>()
            + size_of::<Option<NativeImport18NextValuePassAttemptData<'static>>>()
            + size_of::<&mut Option<NativeImport18NextValuePassAttemptData<'static>>>()
            + size_of::<&Option<NativeImport18NextValuePassAttemptData<'static>>>()
            + size_of::<&mut NativeImport18NextValuePassAttemptData<'static>>() * 2
            + size_of::<&NativeImport18NextValuePassAttemptData<'static>>() * 2
            + size_of::<Vec<Reparse>>()
            + size_of::<Reparse>() * 2
            + size_of::<Option<NativeImport18EffectiveTextAttemptData>>()
            + size_of::<&mut Vec<Reparse>>()
            + size_of::<&Vec<Reparse>>()
            + size_of::<Option<&mut Reparse>>()
            + size_of::<&mut Reparse>()
            + size_of::<&Reparse>()
            + size_of::<Option<&Reparse>>()
            + size_of::<&mut Option<NativeImport18EffectiveTextAttemptData>>()
            + size_of::<&Option<NativeImport18EffectiveTextAttemptData>>()
            + size_of::<&NativeImport18EffectiveTextAttemptData>()
            + size_of::<Option<&NativeImport18EffectiveTextAttemptData>>()
            + size_of::<std::slice::Iter<'static, Reparse>>()
            + size_of::<std::slice::Iter<'static, super::super::Reparse>>()
            + size_of::<NativeImport18NextValueCensusData>()
            + size_of::<&Result<usize, ProviderError>>()
            + size_of::<Result<(), ProviderError>>() * 2
            + size_of::<Result<usize, ProviderError>>() * 3
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<std::collections::TryReserveError>();
        let trees = size_of::<BTreeMap<OwnedValueNodeIdentityData, usize>>()
            + size_of::<&mut BTreeMap<OwnedValueNodeIdentityData, usize>>()
            + size_of::<&BTreeMap<OwnedValueNodeIdentityData, usize>>()
            + size_of::<Entry<'static, OwnedValueNodeIdentityData, usize>>()
            + size_of::<OccupiedEntry<'static, OwnedValueNodeIdentityData, usize>>()
            + size_of::<VacantEntry<'static, OwnedValueNodeIdentityData, usize>>()
            + size_of::<Option<usize>>()
            + size_of::<&OwnedValueNodeIdentityData>()
            + size_of::<Option<&usize>>()
            + size_of::<&usize>();
        let quote_children = size_of::<NativeImport18EffectiveTextConstructionData>() * 2
            + size_of::<Result<NativeImport18EffectiveTextConstructionData, ProviderError>>()
            + size_of::<&NativeImport18EffectiveTextConstructionData>()
            + size_of::<&str>() * 3
            + size_of::<(&str, NativeImport18OwnedValuePassViewData<'static>)>()
            + size_of::<Option<(&str, NativeImport18OwnedValuePassViewData<'static>)>>()
            + size_of::<NativeImport18OwnedValuePassKindData<'static>>()
            + size_of::<Result<NativeImport18OwnedValuePassKindData<'static>, ProviderError>>()
            + size_of::<[usize; 2]>() * 2
            // Actual retained and grown state-initializer sum operands.
            + size_of::<[usize; 4]>()
            + size_of::<[usize; 5]>()
            // Actual prewalk workspace and full quote-total sum operands.
            + size_of::<[usize; 3]>() * 2
            + size_of::<&[usize]>() * 4
            + size_of::<ProviderError>()
            + size_of::<usize>() * 20
            + size_of::<bool>() * 3;
        engine::NextPassStateData::counter_scratch_data()
            + size_of::<input::FirstSource<'static>>() * 4
            + source_recheck
            + rows
            + outputs
            + trees
            + quote_children
            + size_of::<usize>() * 4
            + super::super::walk::counter_scratch_data()
            + super::super::view::counter_scratch_data()
            + walk::counter_scratch_data()
            + view::counter_scratch_data()
            + input::counter_scratch_data()
            + NativeImport18EffectiveTextConstructionData::counter_scratch_data()
    }
}
