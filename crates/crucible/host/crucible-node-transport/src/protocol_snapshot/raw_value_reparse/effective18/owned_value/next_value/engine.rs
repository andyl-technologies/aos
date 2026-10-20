//! Owns the sole next-pass mutable flat state without retaining boundary loans.

use super::*;

pub(super) struct NextPassStateData {
    pub(super) failed: bool,
    pub(super) complete: bool,
    pub(super) mode: Option<RawMode>,
    pub(super) reparses: Vec<Reparse>,
    pub(super) lookup: BTreeMap<OwnedValueNodeIdentityData, usize>,
    pub(super) maximum_intermediate_depth: usize,
}

impl NextPassStateData {
    pub(super) fn new_data() -> Self {
        Self {
            failed: true,
            complete: false,
            mode: None,
            reparses: Vec::new(),
            lookup: BTreeMap::new(),
            maximum_intermediate_depth: 0,
        }
    }

    pub(super) fn run_data(
        &mut self,
        input: NativeImport18NextValueInputData<'_>,
        row: &NativeImport18NextValuePassConstructionData<'_>,
    ) -> Result<(), ProviderError> {
        self.reparses
            .try_reserve_exact(row.reparses)
            .map_err(|_| exhausted())?;
        if self.reparses.capacity() > row.reparses {
            return Err(exhausted());
        }
        // This is the actual fixed probe result retained by this same completed
        // preceding owner, not a caller Boolean or a second feature assumption.
        self.mode = input.selected.loans.first.state_data().mode;
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

    pub(super) fn retained_backing_data(&self, maximum: usize) -> Result<usize, ProviderError> {
        let Self {
            failed: _,
            complete: _,
            mode: _,
            reparses,
            lookup,
            maximum_intermediate_depth: _,
        } = self;
        let mut retained = sum(&[
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

    pub(super) fn counter_scratch_data() -> usize {
        // The actual backing census uses a two-term sum operand.
        size_of::<[usize; 2]>()
            + size_of::<Self>() * 2
            + size_of::<&Self>() * 2
            + size_of::<&mut Self>()
            + size_of::<Option<RawMode>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<usize, ProviderError>>()
    }
}
