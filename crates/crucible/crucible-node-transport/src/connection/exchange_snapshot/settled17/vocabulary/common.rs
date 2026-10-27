//! Checks closed native17 common fields and their actual retained backing.

use super::*;

historical_struct!(ErrorRecord {
    code: String,
    message: String,
    effect: EffectCertainty,
    retryable: bool,
    details: Map<String, Value>,
});

historical_struct!(NotificationBody {
    operation_state: OperationState,
    last_observation_sequence: U64,
    details: Map<String, Value>,
    extensions: Extensions,
});

impl ObserveMetadata for NotificationBody {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            operation_state,
            last_observation_sequence,
            details,
            extensions,
        } = self;
        observer.observe(operation_state)?;
        observer.observe(last_observation_sequence)?;
        observer.observe(details)?;
        observer.observe(extensions)?;
        Ok(())
    }
}

historical_struct!(ObservationBatch {
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

historical_struct!(Bound {
    kind: BoundKind,
    position: Option<Position>,
    evidence: Option<ContentRef>,
});

impl ObserveMetadata for Bound {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            kind,
            position,
            evidence,
        } = self;
        observer.observe(kind)?;
        observer.observe(position)?;
        observer.observe(evidence)?;
        Ok(())
    }
}

macro_rules! unit_enum {
    ($type:ty { $($text:literal => $variant:ident),+ $(,)? }) => {
        impl HistoricalType for $type {
            fn read(input: &[u8], _: &mut Ledger<'_, '_, '_>, build: bool) -> Result<Option<Self>, ProviderError> {
                let value = match plain_string(input)? { $($text => Self::$variant,)+ _ => return Err(invalid()) };
                Ok(build.then_some(value))
            }
        }
    };
}

unit_enum!(BoundaryPolicy { "ordinary_stop" => OrdinaryStop, "input_blocked_park" => InputBlockedPark });

impl ObserveMetadata for BoundaryPolicy {
    fn observe_metadata(&self, _: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        match self {
            Self::OrdinaryStop | Self::InputBlockedPark => Ok(()),
        }
    }
}

unit_enum!(BudgetOutcome { "within_budget" => WithinBudget, "stall" => Stall, "timeout" => Timeout, "fail" => Fail });

impl ObserveMetadata for BudgetOutcome {
    fn observe_metadata(&self, _: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        match self {
            Self::WithinBudget | Self::Stall | Self::Timeout | Self::Fail => Ok(()),
        }
    }
}

unit_enum!(StopReason { "ceiling" => Ceiling, "attention" => Attention, "input_required" => InputRequired, "output" => Output, "idle" => Idle, "canceled" => Canceled, "failed" => Failed });

impl ObserveMetadata for StopReason {
    fn observe_metadata(&self, _: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        match self {
            Self::Ceiling
            | Self::Attention
            | Self::InputRequired
            | Self::Output
            | Self::Idle
            | Self::Canceled
            | Self::Failed => Ok(()),
        }
    }
}

unit_enum!(RetirementDisposition { "consumed" => Consumed, "abandoned_inert_transfer" => AbandonedInertTransfer });

impl ObserveMetadata for RetirementDisposition {
    fn observe_metadata(&self, _: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        match self {
            Self::Consumed | Self::AbandonedInertTransfer => Ok(()),
        }
    }
}

unit_enum!(OperationState { "not_started" => NotStarted, "running" => Running, "completed" => Completed, "unknown" => Unknown });

unit_enum!(EffectCertainty { "not_started" => NotStarted, "in_progress" => InProgress, "completed" => Completed, "unknown" => Unknown });

unit_enum!(Visibility { "staged" => Staged, "committed" => Committed });

unit_enum!(BoundKind { "at" => At, "after" => After, "none_until_activation" => NoneUntilActivation, "unknown" => Unknown });

impl ObserveMetadata for BoundKind {
    fn observe_metadata(&self, _: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        match self {
            Self::At | Self::After | Self::NoneUntilActivation | Self::Unknown => Ok(()),
        }
    }
}

impl HistoricalType for ResponseShape {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let status = plain_string(fields.named("status")?)?;
        let operation_state =
            ledger.read::<OperationState>(fields.named("operation_state")?, build)?;
        let value = match status {
            "accepted" | "completed" => {
                let result = ledger.read::<Map<String, Value>>(fields.named("result")?, build)?;
                let extensions = ledger.read::<Extensions>(fields.named("extensions")?, build)?;
                if build {
                    let operation_state = operation_state.ok_or_else(invalid)?;
                    let result = result.ok_or_else(invalid)?;
                    let extensions = extensions.ok_or_else(invalid)?;
                    Some(if status == "accepted" {
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
                    })
                } else {
                    None
                }
            }
            "error" => {
                let error = ledger.read::<ErrorRecord>(fields.named("error")?, build)?;
                let extensions = ledger.read::<Extensions>(fields.named("extensions")?, build)?;
                if build {
                    Some(Self::Error {
                        operation_state: operation_state.ok_or_else(invalid)?,
                        error: error.ok_or_else(invalid)?,
                        extensions: extensions.ok_or_else(invalid)?,
                    })
                } else {
                    None
                }
            }
            _ => return Err(invalid()),
        };
        fields.finish()?;
        Ok(value)
    }
}

impl ObserveMetadata for ResponseShape {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        match self {
            Self::Accepted {
                operation_state,
                result,
                extensions,
            }
            | Self::Completed {
                operation_state,
                result,
                extensions,
            } => {
                observer.observe(operation_state)?;
                observer.observe(result)?;
                observer.observe(extensions)
            }
            Self::Error {
                operation_state,
                error,
                extensions,
            } => {
                observer.observe(operation_state)?;
                observer.observe(error)?;
                observer.observe(extensions)
            }
        }
    }
}

#[path = "common/native17_build.rs"]
mod native17_build;
