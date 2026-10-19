//! Projects one real owned-Value adapter pass from an existing strict raw tree.
//!
//! Ordinary nodes remain immutable borrowed DATA. Only a real first-key Raw
//! String is parsed, using the separately funded flat text-pass owner. Remaining
//! keys are checked after that parse, matching the locked MapDeserializer. No
//! recursive owned Value, implicit extra adapter pass or live grant is created.
//! The first pass accepts strict raw input. The separate next_value module
//! accepts an explicit first-to-second borrowed boundary; whole owned
//! Envelope/ResponseShape construction remains closed.

use super::*;
use crate::retained_metadata::requested_storage::tree_storage_data;
use crate::transport::RetainedFrame;

mod envelope_fields;
pub(crate) use envelope_fields::{
    EnvelopeField18Data, EnvelopeFieldsCensus18Data, NativeImport18EnvelopeFieldsAttemptData,
    NativeImport18EnvelopeFieldsConstructionData,
};

mod immutable_raw;
pub(crate) use immutable_raw::{
    NativeImport18ImmutableRawBankData, NativeImport18ImmutableRawCensusData,
    NativeImport18ImmutableRawConstructionData, NativeImport18ImmutableRawCustodyData,
    NativeImport18RawChildData, NativeImport18RawSelectionConstructionData,
    NativeImport18RawSelectionData,
};

mod next_value;
pub(crate) use next_value::{
    NativeImport18NextValueCensusData, NativeImport18NextValueInputData,
    NativeImport18NextValuePassArrayData, NativeImport18NextValuePassAttemptData,
    NativeImport18NextValuePassConstructionData, NativeImport18NextValuePassKindData,
    NativeImport18NextValuePassObjectData, NativeImport18NextValuePassViewData,
    NativeImport18NextValuePrewalkData, NativeImport18ResponseShapeCutsData,
    NativeImport18ResponseShapeCutsPreludeData, NativeImport18ResponseValueCutData,
    NativeImport18ResponseValueCutLocationData,
};

mod storage;
mod view;
mod walk;
pub(crate) use storage::NativeImport18OwnedValuePassConstructionData;
pub(crate) use view::{
    NativeImport18OwnedValuePassArrayData, NativeImport18OwnedValuePassKindData,
    NativeImport18OwnedValuePassObjectData, NativeImport18OwnedValuePassViewData,
};

struct Reparse {
    source: *const Value,
    attempt: Option<NativeImport18EffectiveTextAttemptData>,
}

/// Retains a spent strict-raw adapter attempt and every flat reparse partial.
///
/// The actual raw frame remains a separate immutable owning bank. Resource
/// pointer correspondence never authenticates a Source, native phase or quota.
/// The retained construction row immutably borrows the actual raw bank and
/// selected subtree, so completion cannot observe same-address replacement.
pub(crate) struct NativeImport18OwnedValuePassAttemptData<'bank> {
    started: bool,
    failed: bool,
    complete: bool,
    row: NativeImport18OwnedValuePassConstructionData<'bank>,
    mode: Option<RawMode>,
    reparses: Vec<Reparse>,
    lookup: BTreeMap<usize, usize>,
    maximum_intermediate_depth: usize,
}

impl<'bank> NativeImport18OwnedValuePassAttemptData<'bank> {
    /// Installs failure/spent state before quotation recheck or construction.
    ///
    /// The caller independently admits the complete row beside the actual raw
    /// owner and all old phase/controller owners. No source tree is cloned.
    ///
    /// # Errors
    /// Refuses a used slot, altered row, raw depth/layout, lexical/Raw semantics
    /// or storage exhaustion. Every initialized flat child and map prefix stays.
    pub(crate) fn read_into_data(
        raw: &'bank RetainedFrame,
        input: &'bank Value,
        row: &NativeImport18OwnedValuePassConstructionData<'bank>,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(invalid());
        }
        *output = Some(Self {
            started: true,
            failed: true,
            complete: false,
            row: *row,
            mode: None,
            reparses: Vec::new(),
            lookup: BTreeMap::new(),
            maximum_intermediate_depth: 0,
        });
        let owner = output.as_mut().ok_or_else(invalid)?;
        owner.row.authenticate_data(raw, input)?;
        // Recompute actual demand before reserving; pointer equality alone is
        // not a resource proof if an owner were replaced between callbacks.
        let current =
            NativeImport18OwnedValuePassConstructionData::quote_data(raw, input, row.maximum)?;
        if !row.dominates_data(&current) {
            return Err(invalid());
        }
        owner
            .reparses
            .try_reserve_exact(row.reparses)
            .map_err(|_| exhausted())?;
        owner.mode = Some(actual_raw_mode_data()?);
        let mut walk = walk::Walk::new_data(input);
        while let Some((value, depth)) = walk.next_data()? {
            owner.maximum_intermediate_depth = owner.maximum_intermediate_depth.max(depth);
            let Value::Object(fields) = value else {
                continue;
            };
            if !matches!(owner.mode, Some(RawMode::Reparse)) {
                continue;
            }
            let Some((key, payload)) = fields.iter().next() else {
                continue;
            };
            if key != RAW_VALUE_KEY {
                continue;
            }
            let payload = payload.as_str().ok_or_else(invalid)?;
            let position = owner.reparses.len();
            if position >= row.reparses {
                return Err(exhausted());
            }
            owner.reparses.push(Reparse {
                source: value,
                attempt: None,
            });
            if owner
                .lookup
                .insert(value as *const Value as usize, position)
                .is_some()
            {
                return Err(invalid());
            }
            let child = owner.reparses.get_mut(position).ok_or_else(invalid)?;
            let child_row =
                NativeImport18EffectiveTextConstructionData::quote_data(payload, row.maximum)?;
            NativeImport18EffectiveTextAttemptData::read_into_data(
                payload,
                &child_row,
                &mut child.attempt,
            )?;
            let child = child.attempt.as_ref().ok_or_else(invalid)?;
            owner.maximum_intermediate_depth = owner.maximum_intermediate_depth.max(
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
        owner.retained_requested_storage_data(row.retained)?;
        owner.complete = true;
        owner.failed = false;
        Ok(())
    }

    /// Lends the one-pass effective root without another normalization pass.
    ///
    /// # Errors
    /// Refuses a failed/incomplete attempt or a different actual raw frame.
    pub(crate) fn completed_data<'a>(
        &'a self,
        raw: &'a RetainedFrame,
        input: &'a Value,
    ) -> Result<NativeImport18OwnedValuePassViewData<'a>, ProviderError> {
        self.row.authenticate_data(raw, input)?;
        if !self.started || self.failed || !self.complete {
            return Err(invalid());
        }
        Ok(view::raw_data(self, input))
    }

    /// Returns observed source and created flat-child intermediate depth.
    ///
    /// No ordinary Value is materialized at this depth. A later adapter must
    /// independently prove and fund its actual structural construction cut.
    pub(crate) const fn maximum_intermediate_depth_data(&self) -> usize {
        self.maximum_intermediate_depth
    }

    /// Counts actual child capacities and every failed flat/map prefix.
    ///
    /// The original raw owner is separate. Tree accounting is the defining
    /// conservative pinned requested layout, not actual allocator byte facts.
    ///
    /// # Errors
    /// Refuses checked census overflow or the supplied whole requested bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        let Self {
            started: _,
            failed: _,
            complete: _,
            row: _,
            mode: _,
            reparses,
            lookup,
            maximum_intermediate_depth: _,
        } = self;
        let mut retained = storage::sum(&[
            size_of::<Option<Self>>(),
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
}

fn invalid() -> ProviderError {
    ProviderError::Frame("explicit18 owned Value adapter pass")
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("explicit18 owned Value pass workspace")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shallow_value(view: NativeImport18OwnedValuePassViewData<'_>) -> Value {
        match view.kind_data().unwrap() {
            NativeImport18OwnedValuePassKindData::Null => Value::Null,
            NativeImport18OwnedValuePassKindData::Bool(value) => Value::Bool(value),
            NativeImport18OwnedValuePassKindData::Number(value) => Value::Number(value.clone()),
            NativeImport18OwnedValuePassKindData::String(value) => Value::String(value.to_owned()),
            NativeImport18OwnedValuePassKindData::Array(values) => {
                Value::Array(values.map(shallow_value).collect())
            }
            NativeImport18OwnedValuePassKindData::Object(values) => Value::Object(
                values
                    .map(|(key, value)| (key.to_owned(), shallow_value(value)))
                    .collect(),
            ),
        }
    }

    fn assert_locked_owned_pass(value: Value) {
        let raw = RetainedFrame {
            bytes: Vec::new(),
            value,
        };
        let row =
            NativeImport18OwnedValuePassConstructionData::quote_data(&raw, &raw.value, usize::MAX)
                .unwrap();
        let mut attempt = None;
        let actual = NativeImport18OwnedValuePassAttemptData::read_into_data(
            &raw,
            &raw.value,
            &row,
            &mut attempt,
        );
        let expected = serde_json::from_value::<Value>(raw.value.clone());
        assert_eq!(actual.is_ok(), expected.is_ok());
        let owner = attempt.as_ref().unwrap();
        assert!(
            owner.retained_requested_storage_data(usize::MAX).unwrap()
                <= row.requested_storage_data().0
        );
        if let Ok(expected) = expected {
            assert_eq!(
                shallow_value(owner.completed_data(&raw, &raw.value).unwrap()),
                expected
            );
        } else {
            assert!(owner.failed);
            assert!(owner.completed_data(&raw, &raw.value).is_err());
        }
    }

    #[test]
    fn shallow_owned_pass_matches_locked_serde_at_exact_adapter_boundary() {
        for value in [
            Value::Null,
            serde_json::json!([false,1,"text",{"ordinary":null}]),
            serde_json::json!({"$serde_json::private::RawValue":"[true,1]"}),
            serde_json::json!({"!ordinary":0,"$serde_json::private::RawValue":"null"}),
            serde_json::json!({"$serde_json::private::RawValue":"null","z":0}),
            serde_json::json!({"$serde_json::private::RawValue":3}),
            // The text result exposes Raw first only AFTER BTree normalization.
            // This pass must return that object, not silently normalize again.
            serde_json::json!({"$serde_json::private::RawValue":r#"{"z":0,"$serde_json::private::RawValue":"null"}"#}),
        ] {
            assert_locked_owned_pass(value);
        }
    }

    #[test]
    fn late_extra_key_refusal_keeps_completed_flat_deep_child_and_no_retry() {
        let text = format!("{}null{}", "[".repeat(80), "]".repeat(80));
        let raw = RetainedFrame {
            bytes: Vec::new(),
            value: serde_json::json!({"$serde_json::private::RawValue":text,"z":0}),
        };
        let row =
            NativeImport18OwnedValuePassConstructionData::quote_data(&raw, &raw.value, usize::MAX)
                .unwrap();
        let mut attempt = None;
        let result = NativeImport18OwnedValuePassAttemptData::read_into_data(
            &raw,
            &raw.value,
            &row,
            &mut attempt,
        );
        let owner = attempt.as_ref().unwrap();
        if matches!(owner.mode, Some(RawMode::Reparse)) {
            assert!(result.is_err());
            assert!(owner.failed);
            assert_eq!(owner.reparses.len(), 1);
            let child = owner.reparses[0].attempt.as_ref().unwrap();
            assert!(child.completed_data().is_ok());
            assert!(child.maximum_intermediate_depth_data() > 64);
            assert!(owner.completed_data(&raw, &raw.value).is_err());
        } else {
            assert!(result.is_ok());
        }
        let before = owner.retained_requested_storage_data(usize::MAX).unwrap();
        assert!(
            NativeImport18OwnedValuePassAttemptData::read_into_data(
                &raw,
                &raw.value,
                &row,
                &mut attempt
            )
            .is_err()
        );
        assert_eq!(
            attempt
                .as_ref()
                .unwrap()
                .retained_requested_storage_data(usize::MAX)
                .unwrap(),
            before
        );
    }

    #[test]
    fn foreign_subtree_is_not_a_resource_member_even_when_equal() {
        let raw = RetainedFrame {
            bytes: Vec::new(),
            value: serde_json::json!({"literal":null}),
        };
        let foreign = Value::Null;
        assert!(
            NativeImport18OwnedValuePassConstructionData::quote_data(&raw, &foreign, usize::MAX)
                .is_err()
        );
        let own = raw.value.get("literal").unwrap();
        assert!(
            NativeImport18OwnedValuePassConstructionData::quote_data(&raw, own, usize::MAX).is_ok()
        );
    }
}
