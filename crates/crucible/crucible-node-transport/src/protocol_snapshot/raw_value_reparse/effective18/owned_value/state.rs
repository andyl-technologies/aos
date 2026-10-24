//! Owns the sole first-pass normalizer's source-free mutable flat state.
//!
//! Callers retain an actual immutable source guard/selection separately. Engine
//! calls borrow that source briefly and mutate only this disjoint owning state.
//! Failed/overwritten child histories remain here without any success allocation.

use super::*;

pub(super) struct FirstPassStateData {
    pub(super) started: bool,
    pub(super) failed: bool,
    pub(super) complete: bool,
    pub(super) mode: Option<RawMode>,
    pub(super) reparses: Vec<Reparse>,
    pub(super) lookup: BTreeMap<usize, usize>,
    pub(super) maximum_intermediate_depth: usize,
}

impl FirstPassStateData {
    pub(super) fn new_data() -> Self {
        Self {
            started: true,
            failed: true,
            complete: false,
            mode: None,
            reparses: Vec::new(),
            lookup: BTreeMap::new(),
            maximum_intermediate_depth: 0,
        }
    }

    // Source authentication, prospective row admission and final whole-owner
    // census belong to the caller. This is the one unchanged normalization loop.
    pub(super) fn run_data(
        &mut self,
        input: &Value,
        row: &NativeImport18OwnedValuePassConstructionData<'_>,
    ) -> Result<(), ProviderError> {
        self.reparses
            .try_reserve_exact(row.reparses)
            .map_err(|_| exhausted())?;
        self.mode = Some(actual_raw_mode_data()?);
        let mut walk = walk::Walk::new_data(input);
        while let Some((value, depth)) = walk.next_data()? {
            self.maximum_intermediate_depth = self.maximum_intermediate_depth.max(depth);
            let Value::Object(fields) = value else {
                continue;
            };
            if !matches!(self.mode, Some(RawMode::Reparse)) {
                continue;
            }
            let Some((key, payload)) = fields.iter().next() else {
                continue;
            };
            if key != RAW_VALUE_KEY {
                continue;
            }
            let payload = payload.as_str().ok_or_else(invalid)?;
            let position = self.reparses.len();
            if position >= row.reparses {
                return Err(exhausted());
            }
            self.reparses.push(Reparse {
                source: value,
                attempt: None,
            });
            if self
                .lookup
                .insert(value as *const Value as usize, position)
                .is_some()
            {
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
            self.maximum_intermediate_depth = self.maximum_intermediate_depth.max(
                depth
                    .checked_sub(1)
                    .and_then(|parent| parent.checked_add(child.maximum_intermediate_depth_data()))
                    .ok_or_else(exhausted)?,
            );
            // ValueVisitor parses the String before MapDeserializer diagnoses
            // unconsumed fields. Keep that real child even on this late error.
            if fields.len() != 1 {
                return Err(invalid());
            }
            walk.skip_children_data();
        }
        Ok(())
    }

    pub(super) fn retained_backing_data(&self, maximum: usize) -> Result<usize, ProviderError> {
        let Self {
            started: _,
            failed: _,
            complete: _,
            mode: _,
            reparses,
            lookup,
            maximum_intermediate_depth: _,
        } = self;
        let mut retained = storage::sum(&[
            storage::mul(reparses.capacity(), size_of::<Reparse>())?,
            tree_storage_data(
                usize::from(!lookup.is_empty()),
                lookup.len(),
                size_of::<(usize, usize)>(),
                align_of::<usize>(),
            )?,
        ])?;
        for Reparse { source: _, attempt } in reparses {
            if let Some(attempt) = attempt {
                let child = attempt.retained_requested_storage_data(maximum)?;
                retained = storage::add(
                    retained,
                    child
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
        size_of::<Self>() * 2
            + size_of::<&Self>() * 2
            + size_of::<&mut Self>()
            + size_of::<Option<Self>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<&NativeImport18OwnedValuePassConstructionData<'static>>()
            + size_of::<&Value>()
            + size_of::<Vec<Reparse>>()
            + size_of::<&Vec<Reparse>>()
            + size_of::<std::slice::Iter<'static, Reparse>>()
            + size_of::<&Reparse>()
            + size_of::<Option<&NativeImport18EffectiveTextAttemptData>>()
            + size_of::<&NativeImport18EffectiveTextAttemptData>()
            + size_of::<BTreeMap<usize, usize>>()
            + size_of::<&BTreeMap<usize, usize>>()
            + size_of::<std::alloc::Layout>()
            + size_of::<Result<std::alloc::Layout, std::alloc::LayoutError>>()
            + size_of::<[usize; 5]>()
            + size_of::<[usize; 8]>()
            + size_of::<[usize; 2]>()
            + size_of::<&[usize]>()
    }
}
