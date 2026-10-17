//! Observes the actual separately owned common protocol DTO allocations.
//!
//! The closed borrowed variants walk typed fields and spare container capacities.
//! Outer caller enum/header storage and independently encoded buffers remain the
//! caller's terms. Equal values in different owners receive no discount.

use super::*;
use crate::bodies::*;

/// Borrows one closed original common protocol DTO as data.
pub enum RetainedCommonProtocolData<'a> {
    /// Borrows a separately retained Admit response, including raw result data.
    ///
    /// Other decoded method-result families refuse; refusals retain raw errors.
    AdmitResponse(&'a ResponseBody),
    /// Borrows the actual retained DiscoverResult fields.
    Discover(&'a DiscoverResult),
    /// Borrows the actual retained RealizeResult fields.
    Realize(&'a RealizeResult),
    /// Borrows the actual retained BeginRequest fields.
    Begin(&'a BeginRequest),
    /// Borrows the actual retained InputRequest fields.
    InputRequest(&'a InputRequest),
    /// Borrows the actual retained InputResult fields.
    InputResult(&'a InputResult),
    /// Borrows the actual retained WorldActivateResult fields.
    WorldActivate(&'a WorldActivateResult),
}

impl RetainedCommonProtocolData<'_> {
    /// Reports explicit fixed observer, result and borrowed Admit view scratch.
    ///
    /// The owning caller admits this before traversal. Compiler frames, recursive
    /// visitors, allocator rounding and enclosing response storage are separate.
    pub const fn admit_response_counter_scratch_data() -> usize {
        std::mem::size_of::<MetadataObserver<'static>>()
            + std::mem::size_of::<RetainedProtocolMetadataFacts>()
            + std::mem::size_of::<RetainedCommonProtocolData<'static>>()
            + std::mem::size_of::<&ResponseBody>()
            + std::mem::size_of::<&ResponseShape>()
            + std::mem::size_of::<&Option<MethodResult>>()
    }

    /// Reports actual borrowed String/Vec/tree/shared payload layouts.
    ///
    /// No serialization, callback, live source permission or inline outer DTO
    /// header is included. The owning capsule supplies its original-origin guard.
    ///
    /// # Errors
    /// Reports checked traversal/layout overflow or finite observer exhaustion.
    pub fn observe_retained_metadata(
        &self,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::new();
        match self {
            Self::AdmitResponse(value) => observe_admit_response(value, &mut observer)?,
            Self::Discover(value) => observer.observe(*value)?,
            Self::Realize(value) => observer.observe(*value)?,
            Self::Begin(value) => observer.observe(*value)?,
            Self::InputRequest(value) => observer.observe(*value)?,
            Self::InputResult(value) => observer.observe(*value)?,
            Self::WorldActivate(value) => observer.observe(*value)?,
        }
        Ok(observer.finish())
    }
}

fields!(
    DiscoverResult,
    provider_manifest,
    profiles,
    facet_schemas,
    complete,
    next_cursor
);
fields!(
    RealizeResult,
    realization_manifest,
    prepared_token,
    closed_gate_receipt
);
fields!(
    BeginRequest,
    kind,
    binding_hash,
    owner_generation,
    activation_id,
    world_generation,
    arguments,
    extensions
);
fields!(
    InputRequest,
    binding_hash,
    owner_generation,
    batch_id,
    batch_sequence,
    input_epoch,
    events,
    batch_hash,
    extensions
);
fields!(
    InputResult,
    accepted_event_ids,
    input_watermark,
    custody_receipt,
    inventory_hash
);
fields!(
    WorldActivateResult,
    armed_owner_ids,
    gate_id,
    activation_receipt
);

impl ObserveMetadata for BeginKind {
    fn observe_metadata(&self, _: &mut MetadataObserver) -> Result<(), ProviderError> {
        match self {
            Self::ExactRun
            | Self::BoundarySettle
            | Self::QuantumBegin
            | Self::Pause
            | Self::Capture
            | Self::PrepareRestore
            | Self::Shutdown => Ok(()),
        }
    }
}

pub(super) fn observe_admit_response(
    response: &ResponseBody,
    observer: &mut MetadataObserver,
) -> Result<(), ProviderError> {
    let ResponseBody { shape, result } = response;
    match shape {
        ResponseShape::Accepted {
            operation_state,
            result,
            extensions,
        }
        | ResponseShape::Completed {
            operation_state,
            result,
            extensions,
        } => {
            observer.observe(operation_state)?;
            observer.observe(result)?;
            observer.observe(extensions)?;
        }
        ResponseShape::Error {
            operation_state,
            error,
            extensions,
        } => {
            observer.observe(operation_state)?;
            observer.observe(error)?;
            observer.observe(extensions)?;
        }
    }
    match result {
        None => Ok(()),
        Some(MethodResult::Admit(value)) => observer.observe(value),
        Some(
            MethodResult::Hello(_)
            | MethodResult::Discover(_)
            | MethodResult::Realize(_)
            | MethodResult::BeginAccepted(_)
            | MethodResult::Capture(_)
            | MethodResult::Poll(_)
            | MethodResult::Activate(_)
            | MethodResult::Input(_)
            | MethodResult::Observe(_)
            | MethodResult::Cancel(_)
            | MethodResult::QuantumClose(_)
            | MethodResult::WorldActivate(_)
            | MethodResult::Abort(_)
            | MethodResult::Retire(_)
            | MethodResult::BlobBegin(_)
            | MethodResult::BlobChunk(_)
            | MethodResult::BlobFinish(_)
            | MethodResult::Release(_)
            | MethodResult::ExactRun(_)
            | MethodResult::BoundarySettle(_)
            | MethodResult::QuantumBegin(_)
            | MethodResult::Pause(_)
            | MethodResult::PrepareRestore(_)
            | MethodResult::Shutdown(_),
        ) => Err(ProviderError::Correlation(
            "retained Admit result method family differs",
        )),
    }
}

fields!(AdmitResult, accepted_binding_hashes, admission_id);

#[cfg(test)]
mod admit_response_tests {
    use super::*;
    use crucible_node_contract::{HashRef, Id};
    use serde_json::{Map, Value};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn actual_admit_response_counts_independent_raw_and_typed_spare_backing() -> TestResult {
        let mut raw = String::with_capacity(197);
        raw.push_str("independent raw result");
        let raw_capacity = raw.capacity();
        let mut result = Map::new();
        result.insert("retained".into(), Value::String(raw));
        let hashes = Vec::<HashRef>::with_capacity(7);
        let vector_bytes = hashes.capacity() * std::mem::size_of::<HashRef>();
        let response = ResponseBody {
            shape: ResponseShape::Completed {
                operation_state: OperationState::Completed,
                result,
                extensions: Default::default(),
            },
            result: Some(MethodResult::Admit(AdmitResult {
                accepted_binding_hashes: hashes,
                admission_id: Id::new("retained/admission")?,
            })),
        };

        let facts =
            RetainedCommonProtocolData::AdmitResponse(&response).observe_retained_metadata()?;
        assert_eq!(facts.vector_capacity_bytes, vector_bytes);
        assert!(facts.string_capacity_bytes >= raw_capacity + "retained/admission".len());
        assert!(facts.tree_containers >= 2);
        Ok(())
    }

    #[test]
    fn refusal_error_backing_is_counted_and_other_typed_methods_refuse() -> TestResult {
        let mut message = String::with_capacity(211);
        message.push_str("retained failure");
        let capacity = message.capacity();
        let error = ResponseBody {
            shape: ResponseShape::Error {
                operation_state: OperationState::Unknown,
                error: ErrorRecord {
                    code: "OUTCOME_UNKNOWN".into(),
                    message,
                    effect: EffectCertainty::Unknown,
                    retryable: false,
                    details: Default::default(),
                },
                extensions: Default::default(),
            },
            result: None,
        };
        assert!(
            RetainedCommonProtocolData::AdmitResponse(&error)
                .observe_retained_metadata()?
                .string_capacity_bytes
                >= capacity
        );
        let other = ResponseBody {
            shape: error.shape,
            result: Some(MethodResult::BlobChunk(BlobChunkResult {
                transfer_id: Id::new("retained/transfer")?,
                next_offset: crucible_node_contract::U64::new(0),
            })),
        };
        assert!(
            RetainedCommonProtocolData::AdmitResponse(&other)
                .observe_retained_metadata()
                .is_err()
        );
        Ok(())
    }
}
