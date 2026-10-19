//! Quotes actual strict-subtree Raw reparses and observes no protocol grant.
//!
//! The source and selected subtree are real immutable borrowed Values. Their
//! complete sixty-four-container prewalk precedes construction. Each potential
//! first-key String has its own defining text row; no byte cap becomes demand.

use super::*;
use crate::retained_metadata::serialization_storage::{
    OriginalJsonValueStorageExtentData, original_json_value_storage_extent_data,
};

/// Binds actual retained raw/subtree identities to independent pass workspace.
///
/// Real immutable loans retain the raw bytes and decoded selected subtree from
/// quotation through every copied row and successful or failed owning attempt.
/// Pointer checks establish membership only; these loans prevent content rebinding.
#[derive(Clone, Copy)]
pub(crate) struct NativeImport18OwnedValuePassConstructionData<'bank> {
    raw: &'bank RetainedFrame,
    input: &'bank Value,
    pub(super) maximum: usize,
    pub(super) reparses: usize,
    pub(super) retained: usize,
    transient: usize,
    scratch: usize,
}

impl<'bank> NativeImport18OwnedValuePassConstructionData<'bank> {
    pub(super) fn raw_resource_data(&self) -> &'bank RetainedFrame {
        self.raw
    }

    /// Quotes one real selected strict subtree without parsing or allocation.
    ///
    /// The caller admits counter_scratch_data before this bounded borrowed
    /// prewalk. Both possible Raw feature outcomes are priced; the actual fixed
    /// shallow probe runs only after the returned complete row is admitted.
    /// The selected input must be an exact actual member of the retained raw
    /// bank, so this API supports genuine structural field cuts without inventing
    /// an extra root-Value pass over Envelope or ResponseShape maps.
    ///
    /// # Errors
    /// Refuses foreign membership, strict raw depth, overflow, unsupported layout
    /// or requested storage beyond the unchanged caller maximum.
    pub(crate) fn quote_data(
        raw: &'bank RetainedFrame,
        input: &'bank Value,
        maximum: usize,
    ) -> Result<Self, ProviderError> {
        let mut origin = walk::Walk::new_data(&raw.value);
        let mut member = false;
        while let Some((value, _)) = origin.next_data()? {
            member |= std::ptr::eq(value, input);
        }
        if !member {
            return Err(invalid());
        }

        let mut reparses = 0usize;
        let mut child_retained = 0usize;
        let mut child_transient = 0usize;
        let mut child_scratch = 0usize;
        let mut source = walk::Walk::new_data(input);
        while let Some((value, _)) = source.next_data()? {
            let Value::Object(fields) = value else {
                continue;
            };
            let Some((key, Value::String(payload))) = fields.iter().next() else {
                continue;
            };
            if key != RAW_VALUE_KEY {
                continue;
            }
            // Quote all potential markers even in ordinary mode, and retain
            // all source descendants in this prewalk. Reparse mode may stop at
            // an earlier branch or extra-key error; neither alternative can
            // create more text owners than these actual candidate strings.
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
            size_of::<(usize, usize)>(),
            align_of::<usize>(),
        )?;
        let retained = sum(&[
            size_of::<Option<NativeImport18OwnedValuePassAttemptData<'static>>>(),
            mul(reparses, size_of::<Reparse>())?,
            child_retained,
            trees,
        ])?;

        // This is the exact fixed shallow Raw probe constructor, not a donor
        // from a user-text cap. Its root and literal null reparse are separate
        // owners. It drops before any actual child workspace is constructed.
        let probe = original_json_value_storage_extent_data(RAW_PROBE.len())?;
        let (probe_parser, probe_scratch) = geometry::parser_storage_data(RAW_PROBE.len())?;
        let probe_transient = mul(2, add(probe.value_dom_requested_bytes, probe_parser)?)?;
        let initializer = sum(&[
            size_of::<NativeImport18OwnedValuePassAttemptData<'static>>(),
            size_of::<Option<NativeImport18OwnedValuePassAttemptData<'static>>>(),
            size_of::<Vec<Reparse>>(),
            size_of::<BTreeMap<usize, usize>>(),
            // The inline Reparse initializer and its owning Vec::push argument.
            size_of::<Reparse>(),
            size_of::<Reparse>(),
        ])?;
        // Map insertion can allocate root/split nodes while old lookup backing
        // remains live. Its independently priced construction window uses the
        // same pinned classes and actual candidate population as retained R.
        let tree_constructor = tree_storage_data(
            reparses,
            reparses,
            size_of::<(usize, usize)>(),
            align_of::<usize>(),
        )?;
        let transient = child_transient
            .max(probe_transient)
            .max(initializer)
            .max(tree_constructor);
        let scratch = add(
            Self::counter_scratch_data(),
            child_scratch.max(mul(2, probe_scratch)?),
        )?;
        if sum(&[retained, transient, scratch])? > maximum {
            return Err(exhausted());
        }
        Ok(Self {
            raw,
            input,
            maximum,
            reparses,
            retained,
            transient,
            scratch,
        })
    }

    pub(super) fn authenticate_data(
        &self,
        raw: &RetainedFrame,
        input: &Value,
    ) -> Result<(), ProviderError> {
        if !std::ptr::eq(self.raw, raw) || !std::ptr::eq(self.input, input) {
            return Err(invalid());
        }
        Ok(())
    }

    pub(super) fn dominates_data(&self, current: &Self) -> bool {
        std::ptr::eq(self.raw, current.raw)
            && std::ptr::eq(self.input, current.input)
            && self.maximum == current.maximum
            && current.reparses <= self.reparses
            && current.retained <= self.retained
            && current.transient <= self.transient
            && current.scratch <= self.scratch
    }

    /// Returns independent retained workspace, constructor transient and scratch.
    pub(crate) const fn requested_storage_data(&self) -> (usize, usize, usize) {
        (self.retained, self.transient, self.scratch)
    }

    /// Names actual strict-walk, text quote, lookup, view and partial controls.
    pub(crate) fn counter_scratch_data() -> usize {
        // The returned immutable bank loan binds content lifetime; comparing
        // its address establishes membership and supplies no authority.
        let raw_resource = size_of::<&Self>() + size_of::<&RetainedFrame>();
        raw_resource + walk::counter_scratch_data()
            // Both quote walkers coexist with the fixed initializer output.
            + size_of::<walk::Walk<'static>>() * 2
            + view::counter_scratch_data()
            + NativeImport18EffectiveTextConstructionData::counter_scratch_data()
            + geometry::quote_counter_scratch_data()
            + size_of::<Self>()
            + size_of::<&Self>()
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<NativeImport18OwnedValuePassAttemptData<'static>>()
            + size_of::<Option<NativeImport18OwnedValuePassAttemptData<'static>>>()
            + size_of::<&NativeImport18OwnedValuePassAttemptData<'static>>()
            + size_of::<&mut NativeImport18OwnedValuePassAttemptData<'static>>()
            + size_of::<Option<&mut NativeImport18OwnedValuePassAttemptData<'static>>>()
            + size_of::<Result<&mut NativeImport18OwnedValuePassAttemptData<'static>, ProviderError>>()
            + size_of::<&mut Option<NativeImport18OwnedValuePassAttemptData<'static>>>()
            + size_of::<Reparse>()
            + size_of::<&Reparse>()
            + size_of::<&mut Reparse>()
            + size_of::<Option<&mut Reparse>>()
            + size_of::<Result<&mut Reparse, ProviderError>>()
            + size_of::<std::slice::Iter<'static, Reparse>>()
            + size_of::<&Option<NativeImport18EffectiveTextAttemptData>>()
            + size_of::<Option<&NativeImport18EffectiveTextAttemptData>>()
            + size_of::<Result<&NativeImport18EffectiveTextAttemptData, ProviderError>>()
            + size_of::<&mut Option<NativeImport18EffectiveTextAttemptData>>()
            + size_of::<NativeImport18EffectiveTextConstructionData>()
            + size_of::<Result<NativeImport18EffectiveTextConstructionData, ProviderError>>()
            + size_of::<OriginalJsonValueStorageExtentData>()
            + size_of::<(usize, usize)>()
            + size_of::<Result<(usize, usize), ProviderError>>()
            + size_of::<Value>()
            + size_of::<Result<Value, serde_json::Error>>()
            + size_of::<&str>()
            + size_of::<&String>()
            + size_of::<&serde_json::Map<String, Value>>()
            + size_of::<&RetainedFrame>()
            + size_of::<&Value>()
            + size_of::<RawMode>()
            + size_of::<Option<RawMode>>()
            + size_of::<Result<RawMode, ProviderError>>()
            + size_of::<BTreeMap<usize, usize>>()
            + size_of::<std::collections::btree_map::Entry<'static, usize, usize>>()
            + size_of::<std::collections::btree_map::OccupiedEntry<'static, usize, usize>>()
            + size_of::<std::collections::btree_map::VacantEntry<'static, usize, usize>>()
            + size_of::<(usize, usize)>()
            + size_of::<Option<usize>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<std::collections::TryReserveError>()
            + size_of::<[usize; 6]>()
            + size_of::<[usize; 4]>()
            + size_of::<&[usize]>()
            + size_of::<std::slice::Iter<'static, usize>>()
            + size_of::<[usize; 3]>()
            + size_of::<bool>()
            // Fourteen quote scalars (thirteen locals plus maximum), four
            // constructor depth/index operands, three census scalars, the fold
            // total, lookup address and depth-getter output are actual controls.
            + size_of::<usize>() * 24
    }
}

pub(super) fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(exhausted)
}

pub(super) fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(exhausted)
}

pub(super) fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values
        .iter()
        .try_fold(0usize, |total, value| add(total, *value))
}
