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
    NativeImport18EnvelopeFieldsConstructionData, NativeImport18OwningEnvelopeAttemptData,
    NativeImport18OwningEnvelopeCensusData,
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
    NativeImport18FirstBankCensusData, NativeImport18FirstBankConstructionData,
    NativeImport18FirstBankCustodyData, NativeImport18FirstBankData, NativeImport18FirstChildData,
    NativeImport18FirstSelectionConstructionData, NativeImport18FirstSelectionData,
    NativeImport18NextValueCensusData, NativeImport18NextValueInputData,
    NativeImport18NextValuePassArrayData, NativeImport18NextValuePassAttemptData,
    NativeImport18NextValuePassConstructionData, NativeImport18NextValuePassKindData,
    NativeImport18NextValuePassObjectData, NativeImport18NextValuePassViewData,
    NativeImport18NextValuePrewalkData, NativeImport18OwningNextAttemptData,
    NativeImport18OwningNextCensusData, NativeImport18OwningResponseActionData,
    NativeImport18OwningResponseAttemptData, NativeImport18OwningResponseCensusData,
    NativeImport18ResponseShapeCutsData, NativeImport18ResponseShapeCutsPreludeData,
    NativeImport18ResponseValueCutData, NativeImport18ResponseValueCutLocationData,
};

mod owning_first;
mod state;
mod state_view;

mod storage;
mod view;
mod walk;
pub(crate) use owning_first::{
    NativeImport18OwningFirstAttemptData, NativeImport18OwningFirstCensusData,
    NativeImport18OwningFirstConstructionData,
};
pub(crate) use state_view::{
    NativeImport18FirstFlatArrayData, NativeImport18FirstFlatKindData,
    NativeImport18FirstFlatObjectData, NativeImport18FirstFlatViewData,
};
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
    row: NativeImport18OwnedValuePassConstructionData<'bank>,
    state: state::FirstPassStateData,
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
            row: *row,
            state: state::FirstPassStateData::new_data(),
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
        owner.state.run_data(input, row)?;
        owner.retained_requested_storage_data(row.retained)?;
        owner.state.complete = true;
        owner.state.failed = false;
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
        if !self.state.started || self.state.failed || !self.state.complete {
            return Err(invalid());
        }
        Ok(view::raw_data(self, input))
    }

    /// Returns observed source and created flat-child intermediate depth.
    ///
    /// No ordinary Value is materialized at this depth. A later adapter must
    /// independently prove and fund its actual structural construction cut.
    pub(crate) const fn maximum_intermediate_depth_data(&self) -> usize {
        self.state.maximum_intermediate_depth
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
        let Self { row: _, state } = self;
        let retained = storage::add(
            size_of::<Option<Self>>(),
            state.retained_backing_data(maximum)?,
        )?;
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
            assert!(owner.state.failed);
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
        if matches!(owner.state.mode, Some(RawMode::Reparse)) {
            assert!(result.is_err());
            assert!(owner.state.failed);
            assert_eq!(owner.state.reparses.len(), 1);
            let child = owner.state.reparses[0].attempt.as_ref().unwrap();
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
