//! Reconstructs each native17 field into a retained concrete owner.

use super::*;
use crate::protocol_snapshot::owned11::typed::native17_build::native17_struct;

native17_struct!(ErrorRecord {
    code: String,
    message: String,
    effect: EffectCertainty,
    retryable: bool,
    details: Map<String, Value>,
});

native17_struct!(NotificationBody {
    operation_state: OperationState,
    last_observation_sequence: U64,
    details: Map<String, Value>,
    extensions: Extensions,
});

native17_struct!(ObservationBatch {
    schema_version: Version,
    execution_owner_id: Id,
    owner_binding_hash: HashRef,
    world_binding_hash: HashRef,
    activation_id: Id,
    world_generation: U64,
    owner_generation: U64,
    operation_id: Id,
    grant_id: Option<Id>,
    first_sequence: U64,
    last_sequence: U64,
    events: Vec<Event>,
    visibility: Visibility,
    measurement_ref: ContentRef,
    extensions: Extensions,
});

native17_struct!(Bound {
    kind: BoundKind,
    position: Option<Position>,
    evidence: Option<ContentRef>,
});

use crate::protocol_snapshot::owned11::typed::{
    Native17Build,
    native17_build::{Native17ChildSlot, Native17Field},
};

/// Keeps tagged response fields independently until its final suffix is checked.
#[derive(Default)]
pub(crate) struct ResponseShape17ReadAttempt {
    state: Native17Field<OperationState>,
    result: Native17Field<Map<String, Value>>,
    error: Native17Field<ErrorRecord>,
    extensions: Native17Field<Extensions>,
    output: Option<ResponseShape>,
    started: bool,
    failed: bool,
}

impl Native17Build for ResponseShape {
    type Attempt = ResponseShape17ReadAttempt;

    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        let mut fields = Fields::object(input)?;
        let status = plain_string(fields.named("status")?)?;
        if !matches!(status, "accepted" | "completed" | "error") {
            return Err(invalid());
        }
        let state = fields.named("operation_state")?;
        Native17ChildSlot::<<OperationState as Native17Build>::Attempt>::preflight_data(ledger)?;
        OperationState::preflight_data(state, ledger)?;
        if status == "error" {
            let error = fields.named("error")?;
            Native17ChildSlot::<<ErrorRecord as Native17Build>::Attempt>::preflight_data(ledger)?;
            ErrorRecord::preflight_data(error, ledger)?;
        } else {
            let result = fields.named("result")?;
            Native17ChildSlot::<<Map<String, Value> as Native17Build>::Attempt>::preflight_data(
                ledger,
            )?;
            Map::<String, Value>::preflight_data(result, ledger)?;
        }
        let extensions = fields.named("extensions")?;
        Native17ChildSlot::<<Extensions as Native17Build>::Attempt>::preflight_data(ledger)?;
        Extensions::preflight_data(extensions, ledger)?;
        fields.finish()
    }

    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        let repeated = std::mem::replace(&mut attempt.started, true);
        attempt.failed = true;
        if repeated {
            return Err(invalid());
        }
        let mut fields = Fields::object(input)?;
        let status = plain_string(fields.named("status")?)?;
        if !matches!(status, "accepted" | "completed" | "error") {
            return Err(invalid());
        }
        let state = fields.named("operation_state")?;
        let child = attempt.state.child.begin_data(ledger)?;
        OperationState::read_into_data(state, ledger, child)?;
        attempt.state.output = OperationState::take_output_data(child);
        if attempt.state.output.is_none() {
            return Err(invalid());
        }
        if status == "error" {
            let error = fields.named("error")?;
            let child = attempt.error.child.begin_data(ledger)?;
            ErrorRecord::read_into_data(error, ledger, child)?;
            attempt.error.output = ErrorRecord::take_output_data(child);
            if attempt.error.output.is_none() {
                return Err(invalid());
            }
        } else {
            let result = fields.named("result")?;
            let child = attempt.result.child.begin_data(ledger)?;
            Map::<String, Value>::read_into_data(result, ledger, child)?;
            attempt.result.output = Map::<String, Value>::take_output_data(child);
            if attempt.result.output.is_none() {
                return Err(invalid());
            }
        }
        let extensions = fields.named("extensions")?;
        let child = attempt.extensions.child.begin_data(ledger)?;
        Extensions::read_into_data(extensions, ledger, child)?;
        attempt.extensions.output = Extensions::take_output_data(child);
        if attempt.extensions.output.is_none() {
            return Err(invalid());
        }
        fields.finish()?;
        if status == "error" {
            match (
                attempt.state.output.take(),
                attempt.error.output.take(),
                attempt.extensions.output.take(),
            ) {
                (Some(operation_state), Some(error), Some(extensions)) => {
                    attempt.output = Some(Self::Error {
                        operation_state,
                        error,
                        extensions,
                    });
                }
                (state, error, extensions) => {
                    attempt.state.output = state;
                    attempt.error.output = error;
                    attempt.extensions.output = extensions;
                    return Err(invalid());
                }
            }
        } else {
            match (
                attempt.state.output.take(),
                attempt.result.output.take(),
                attempt.extensions.output.take(),
            ) {
                (Some(operation_state), Some(result), Some(extensions)) => {
                    attempt.output = Some(if status == "accepted" {
                        Self::Accepted {
                            operation_state,
                            result,
                            extensions,
                        }
                    } else {
                        Self::Completed {
                            operation_state,
                            result,
                            extensions,
                        }
                    });
                }
                (state, result, extensions) => {
                    attempt.state.output = state;
                    attempt.result.output = result;
                    attempt.extensions.output = extensions;
                    return Err(invalid());
                }
            }
        }
        attempt.failed = false;
        Ok(())
    }

    fn output_data(attempt: &Self::Attempt) -> Option<&Self> {
        if attempt.failed {
            None
        } else {
            attempt.output.as_ref()
        }
    }
    fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self> {
        if attempt.failed {
            None
        } else {
            attempt.output.take()
        }
    }

    fn observe_attempt_data(
        attempt: &Self::Attempt,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        attempt.state.child.observe_backing_data(observer)?;
        if let Some(child) = attempt.state.child.child_data() {
            OperationState::observe_attempt_data(child, observer)?;
        }
        attempt.result.child.observe_backing_data(observer)?;
        if let Some(child) = attempt.result.child.child_data() {
            Map::<String, Value>::observe_attempt_data(child, observer)?;
        }
        attempt.error.child.observe_backing_data(observer)?;
        if let Some(child) = attempt.error.child.child_data() {
            ErrorRecord::observe_attempt_data(child, observer)?;
        }
        attempt.extensions.child.observe_backing_data(observer)?;
        if let Some(child) = attempt.extensions.child.child_data() {
            Extensions::observe_attempt_data(child, observer)?;
        }
        if let Some(value) = &attempt.state.output {
            OperationState::observe_output_data(value, observer)?;
        }
        if let Some(value) = &attempt.result.output {
            Map::<String, Value>::observe_output_data(value, observer)?;
        }
        if let Some(value) = &attempt.error.output {
            ErrorRecord::observe_output_data(value, observer)?;
        }
        if let Some(value) = &attempt.extensions.output {
            Extensions::observe_output_data(value, observer)?;
        }
        if let Some(value) = &attempt.output {
            Self::observe_output_data(value, observer)?;
        }
        Ok(())
    }

    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(value)
    }
}

#[cfg(test)]
mod retained_response_tests {
    use super::*;
    use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
    use crate::retained_metadata::records::{MetadataRecordBank, ValidatedMetadataRecords};

    fn limits() -> HistoricalJsonLimits {
        HistoricalJsonLimits {
            maximum_input_bytes: 65_536,
            maximum_nodes: 4096,
            maximum_depth: 64,
            maximum_owned_backing_bytes: 1024 * 1024,
            maximum_tree_entries: 128,
        }
    }

    fn responses() -> [ResponseShape; 3] {
        let result = serde_json::json!({"retained":"complete result"})
            .as_object()
            .unwrap()
            .clone();
        [
            ResponseShape::Accepted {
                operation_state: OperationState::Running,
                result: result.clone(),
                extensions: Extensions::new(),
            },
            ResponseShape::Completed {
                operation_state: OperationState::Completed,
                result,
                extensions: Extensions::new(),
            },
            ResponseShape::Error {
                operation_state: OperationState::Unknown,
                error: ErrorRecord {
                    code: "retained-error".into(),
                    message: "complete retained error".into(),
                    effect: EffectCertainty::Unknown,
                    retryable: false,
                    details: Map::new(),
                },
                extensions: Extensions::new(),
            },
        ]
    }

    #[test]
    fn selected_response_variant_prices_and_retains_its_actual_children()
    -> Result<(), Box<dyn std::error::Error>> {
        for original in responses() {
            let input = serde_json::to_vec(&original)?;
            let mut records = MetadataRecordBank::reserve(128)?;
            let mut observer = MetadataObserver::recording(&mut records);
            observer.observe(&original)?;
            let facts = observer.finish();
            let encoded = serde_json::to_vec(&records)?;
            let rows = ValidatedMetadataRecords::validate(
                &encoded,
                facts.capacity_records,
                limits().maximum_owned_backing_bytes,
            )?;
            let mut preflight = Ledger::new(rows.rows(), limits());
            preflight.begin_native17_targets_data(limits().maximum_owned_backing_bytes)?;
            preflight.native17_target_embedded_root_data()?;
            ResponseShape::preflight_data(&input, &mut preflight)?;
            assert!(preflight.rows.next().is_none());
            let exact = preflight.finish_native17_targets_data()?;

            let mut ledger = Ledger::new(rows.rows(), limits());
            ledger.begin_native17_targets_data(exact)?;
            ledger.native17_target_embedded_root_data()?;
            let mut attempt = ResponseShape17ReadAttempt::default();
            ResponseShape::read_into_data(&input, &mut ledger, &mut attempt)?;
            assert_eq!(ledger.finish_native17_targets_data()?, exact);
            assert!(ledger.rows.next().is_none());
            let restored = ResponseShape::take_output_data(&mut attempt).ok_or_else(invalid)?;
            assert_eq!(serde_json::to_vec(&restored)?, input);
            assert!(attempt.state.child.child_data().is_some());
            assert!(attempt.extensions.child.child_data().is_some());
            assert_ne!(
                attempt.error.child.child_data().is_some(),
                attempt.result.child.child_data().is_some()
            );

            let mut changed = input.clone();
            assert_eq!(changed.pop(), Some(b'}'));
            changed.extend_from_slice(br#","unexpected":false}"#);
            let mut ledger = Ledger::new(rows.rows(), limits());
            ledger.begin_native17_targets_data(exact)?;
            ledger.native17_target_embedded_root_data()?;
            let mut partial = ResponseShape17ReadAttempt::default();
            assert!(ResponseShape::read_into_data(&changed, &mut ledger, &mut partial).is_err());
            assert!(partial.output.is_none());
            assert!(partial.state.output.is_some());
            assert!(partial.extensions.output.is_some());
            assert_ne!(
                partial.error.output.is_some(),
                partial.result.output.is_some()
            );
            let mut observer = MetadataObserver::new();
            ResponseShape::observe_attempt_data(&partial, &mut observer)?;
            let retained = observer.finish();
            assert!(retained.vector_capacity_bytes > 0);
            let cursor = ledger.rows.encoded_position();

            assert!(ResponseShape::read_into_data(&input, &mut ledger, &mut partial).is_err());
            assert_eq!(ledger.rows.encoded_position(), cursor);
            let mut observer = MetadataObserver::new();
            ResponseShape::observe_attempt_data(&partial, &mut observer)?;
            assert_eq!(observer.finish(), retained);
        }
        Ok(())
    }
}
