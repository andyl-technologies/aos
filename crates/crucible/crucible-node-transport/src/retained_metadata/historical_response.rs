//! Borrows complete restoration and suffix response partials as inert history.
//!
//! ```text
//! {shape: actual_common_shape, result: null | {kind: closed_method, data: typed}}
//! ```
//!
//! Raw shape and typed result are separate retained owners even when they
//! disagree. There is no decoder or conversion into a live response/claim.
//! Existing Bytes serialization may allocate a temporary; callers separately
//! admit its explicit bound plus output Value/String/canonical ownership.

use super::{MetadataObserver, RetainedProtocolMetadataFacts};
use crate::ProviderError;
use crate::bodies::{MethodResult, ResponseBody, ResponseShape};
use crate::reference_packet::service::complete_restore::activation;
use serde::{Serialize, ser::SerializeStruct};
use std::mem::size_of;

/// Borrows one actual complete raw/typed partial without authenticating it.
pub struct HistoricalResponseBodyData<'a> {
    original: &'a ResponseBody,
}

/// Borrows supported original Admit/restore, activation, Capture and suffix data.
///
/// This performs only a closed Copy discriminator check. No serialization,
/// metadata walk, allocation, native callback or live predicate runs here.
///
/// # Errors
/// Refuses other typed method families; raw error/unfinished shapes are retained.
pub fn historical_response_body_data(
    original: &ResponseBody,
) -> Result<HistoricalResponseBodyData<'_>, ProviderError> {
    match &original.result {
        None => {}
        Some(
            MethodResult::Admit(_)
            | MethodResult::Activate(_)
            | MethodResult::WorldActivate(_)
            | MethodResult::PrepareRestore(_)
            | MethodResult::Capture(_)
            | MethodResult::BeginAccepted(_)
            | MethodResult::Input(_)
            | MethodResult::Observe(_)
            | MethodResult::Poll(_)
            | MethodResult::ExactRun(_)
            | MethodResult::BoundarySettle(_)
            | MethodResult::Retire(_)
            | MethodResult::BlobBegin(_)
            | MethodResult::BlobChunk(_)
            | MethodResult::BlobFinish(_),
        ) => {}
        Some(_) => return Err(unsupported()),
    }
    Ok(HistoricalResponseBodyData { original })
}

impl HistoricalResponseBodyData<'_> {
    pub(crate) fn observe_retained_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observe_response(self.original, observer)
    }

    /// Walks the identical owning field traversal used by its existing family.
    ///
    /// # Errors
    /// Refuses finite traversal, unsupported children or checked extent overflow.
    pub fn retained_metadata_data(&self) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::new();
        observe_response(self.original, &mut observer)?;
        Ok(observer.finish())
    }

    /// Records this owner's complete capacities into independent finite banks.
    ///
    /// The two banks are cleared before the walk; exhaustion leaves partial
    /// rows. No growth occurs. Caller-owned separate banks preserve each owner.
    ///
    /// # Errors
    /// Refuses traversal/overflow or either original finite bank's capacity.
    pub fn record_historical_metadata_data(
        &self,
        records: &mut super::records::MetadataRecordBank,
        aliases: &mut super::aliases::MetadataAliasBank,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::recording_with_aliases(records, aliases);
        observe_response(self.original, &mut observer)?;
        Ok(observer.finish())
    }

    /// Bounds the largest actual Bytes base64 temporary independently of output.
    ///
    /// # Errors
    /// Refuses metadata traversal or checked base64 extent overflow.
    pub fn historical_serialization_transient_bytes_data(&self) -> Result<usize, ProviderError> {
        super::historical_serialization_transient_data(self.retained_metadata_data()?)
    }
}

impl Serialize for HistoricalResponseBodyData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let ResponseBody { shape, result } = self.original;
        let mut state = serializer.serialize_struct("HistoricalResponseBody", 2)?;
        state.serialize_field("shape", shape)?;
        state.serialize_field("result", &result.as_ref().map(HistoricalMethodResult))?;
        state.end()
    }
}

struct HistoricalMethodResult<'a>(&'a MethodResult);

impl Serialize for HistoricalMethodResult<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("HistoricalMethodResult", 2)?;
        macro_rules! body {
            ($name:literal, $value:expr) => {{
                state.serialize_field("kind", $name)?;
                state.serialize_field("data", $value)?;
            }};
        }
        match self.0 {
            MethodResult::Admit(value) => body!("admit", value),
            MethodResult::Activate(value) => body!("activate", value),
            MethodResult::WorldActivate(value) => body!("world_activate", value),
            MethodResult::PrepareRestore(value) => body!("prepare_restore", value),
            MethodResult::Capture(value) => body!("capture", value),
            MethodResult::BeginAccepted(value) => body!("begin_accepted", value),
            MethodResult::Input(value) => body!("input", value),
            MethodResult::Observe(value) => body!("observe", value),
            MethodResult::Poll(value) => body!("poll", value),
            MethodResult::ExactRun(value) => body!("exact_run", value),
            MethodResult::BoundarySettle(value) => body!("boundary_settle", value),
            MethodResult::Retire(value) => body!("retire", value),
            MethodResult::BlobBegin(value) => body!("blob_begin", value),
            MethodResult::BlobChunk(value) => body!("blob_chunk", value),
            MethodResult::BlobFinish(value) => body!("blob_finish", value),
            _ => {
                return Err(serde::ser::Error::custom(
                    "historical response method family differs",
                ));
            }
        }
        state.end()
    }
}

fn observe_response(
    response: &ResponseBody,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    match &response.result {
        Some(MethodResult::Admit(_)) => {
            super::common_data::observe_admit_response(response, observer)
        }
        Some(MethodResult::PrepareRestore(_)) => {
            super::restore_transfer_data::observe_response_metadata_data(response, observer)
        }
        Some(MethodResult::Activate(_) | MethodResult::WorldActivate(_)) => {
            activation::observe_retained_response_metadata_data(response, observer)
        }
        Some(MethodResult::Capture(_)) => super::capture_data::observe_response(response, observer),
        _ => super::restored_suffix::response(response, observer),
    }
}

/// Names all new borrowed layouts and the exact defining family walkers.
pub fn historical_response_body_counter_scratch_data() -> usize {
    super::historical_serialization_counter_scratch_data()
        + super::RetainedCommonProtocolData::admit_response_counter_scratch_data()
        + super::original_complete_restore_transfer_response_counter_scratch_data()
        + super::restored_suffix::counter_scratch_data()
        + activation::restoration_activation_retained_counter_scratch_data()
        + size_of::<HistoricalResponseBodyData<'static>>()
        + size_of::<Result<HistoricalResponseBodyData<'static>, ProviderError>>()
        + size_of::<&HistoricalResponseBodyData<'static>>()
        + size_of::<HistoricalMethodResult<'static>>()
        + size_of::<Option<HistoricalMethodResult<'static>>>()
        + size_of::<&Option<HistoricalMethodResult<'static>>>()
        + size_of::<&ResponseBody>()
        + size_of::<&ResponseShape>()
        + size_of::<&Option<MethodResult>>()
        + size_of::<Option<&MethodResult>>()
        + size_of::<&MethodResult>()
        + size_of::<(
            &crucible_node_format::ContentRef,
            &Vec<crucible_node_format::ContentRef>,
            &crucible_node_format::ContentRef,
        )>()
        + size_of::<&mut super::records::MetadataRecordBank>()
        + size_of::<&mut super::aliases::MetadataAliasBank>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<&crate::bodies::AdmitResult>()
        + size_of::<&crate::bodies::ActivateResult>()
        + size_of::<&crate::bodies::WorldActivateResult>()
        + size_of::<&crate::bodies::PrepareRestoreResult>()
        + size_of::<&crate::bodies::CaptureResult>()
        + size_of::<&crate::bodies::BeginAccepted>()
        + size_of::<&crate::bodies::InputResult>()
        + size_of::<&crate::bodies::ObserveResult>()
        + size_of::<&crate::bodies::PollResult>()
        + size_of::<&crate::bodies::ExactRunResult>()
        + size_of::<&crate::bodies::RetireResult>()
        + size_of::<&crate::bodies::BlobBeginResult>()
        + size_of::<&crate::bodies::BlobChunkResult>()
        + size_of::<&crate::bodies::BlobFinishResult>()
}

fn unsupported() -> ProviderError {
    ProviderError::Correlation("historical response method family differs")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::{Id, canonical};

    #[test]
    fn historical_response_preserves_actual_world_partial_and_record_walk() {
        let response = ResponseBody {
            shape: ResponseShape::Accepted {
                operation_state: crate::bodies::OperationState::Running,
                result: serde_json::Map::from_iter([(
                    "raw_only".into(),
                    serde_json::json!("partial"),
                )]),
                extensions: Default::default(),
            },
            result: Some(MethodResult::WorldActivate(
                crate::bodies::WorldActivateResult {
                    armed_owner_ids: vec![Id::new("actual-typed-owner").unwrap()],
                    gate_id: Id::new("actual-typed-gate").unwrap(),
                    activation_receipt: canonical::content_ref(
                        b"typed-receipt-DATA",
                        "application/json",
                    )
                    .unwrap(),
                },
            )),
        };
        let historical = historical_response_body_data(&response).unwrap();
        let value = serde_json::to_value(&historical).unwrap();
        assert_eq!(value["shape"]["result"]["raw_only"], "partial");
        assert_eq!(value["result"]["kind"], "world_activate");
        assert_eq!(value["result"]["data"]["gate_id"], "actual-typed-gate");

        let expected = activation::RetainedRestorationActivationData::Response(&response)
            .original_retained_metadata_facts()
            .unwrap();
        let mut records =
            super::super::records::MetadataRecordBank::reserve(expected.capacity_records).unwrap();
        let mut aliases = super::super::aliases::MetadataAliasBank::reserve(64).unwrap();
        assert_eq!(
            historical
                .record_historical_metadata_data(&mut records, &mut aliases)
                .unwrap(),
            expected
        );
        assert_eq!(records.rows().len(), expected.capacity_records);
        assert_eq!(
            historical
                .historical_serialization_transient_bytes_data()
                .unwrap(),
            super::super::historical_serialization_transient_data(expected).unwrap()
        );
    }
}
