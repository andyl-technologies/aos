//! Borrows exhaustive suffix partials as inert historical data.
//!
//! The Source owns separate precharged capacity/alias banks. The borrowed value
//! includes raw and independently decoded partials even when they disagree.
//! Process/thread/controller identity and operational Instant are never portable
//! authority. A cut-presence bit records custody without renewing a deadline.
//!
//! ```text
//! {schema,request_id,operation_id,method,cut_present,completed_frontier,
//!  original,response,decoded,roots,stage}
//! decoded = null | {shape, result:null | {kind,data}}
//! ```

use super::*;
use crate::retained_metadata::{
    RetainedProtocolMetadataFacts, aliases::MetadataAliasBank, records::MetadataRecordBank,
};
use serde::ser::SerializeStruct;

/// Borrows the actual partial owner without authenticating any historical state.
///
/// This wrapper has no constructor, decoder or live conversion. Its independent
/// capacity record stream comes from the same exhaustive owning walk.
pub struct OriginalRestoredSuffixHostHistoricalData<'a> {
    original: &'a OriginalRestoredSuffixHostAttempt,
}

impl OriginalRestoredSuffixHostAttempt {
    /// Borrows every retained request, terminal, typed partial and stage as DATA.
    ///
    /// # Errors
    /// Refuses a typed result outside the closed suffix response family. No
    /// currentness, terminal correlation or operational deadline is inferred.
    pub fn historical_data(
        &self,
    ) -> Result<OriginalRestoredSuffixHostHistoricalData<'_>, ProviderError> {
        if let Some(body) = &self.decoded {
            validate_result(body.result.as_ref())?;
        }
        Ok(OriginalRestoredSuffixHostHistoricalData { original: self })
    }

    /// Records actual child capacities into separately precharged finite banks.
    ///
    /// Both supplied banks are cleared before this one owner's walk. Callers
    /// retain independent banks for independent owners. Exhaustion preserves the
    /// partial rows; this method performs no growth, copy or external callback.
    ///
    /// # Errors
    /// Refuses unsupported children, arithmetic/depth overflow or either bank's
    /// original finite capacity. Neither records nor aliases issue live rights.
    pub fn record_historical_metadata_data(
        &self,
        records: &mut MetadataRecordBank,
        aliases: &mut MetadataAliasBank,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer =
            crate::retained_metadata::MetadataObserver::recording_with_aliases(records, aliases);
        self.observe_historical_metadata_data(&mut observer)?;
        Ok(observer.finish())
    }

    /// Names the fixed borrowed history, record and serializer-result views.
    pub fn historical_counter_scratch_data() -> usize {
        Self::counter_scratch_data()
            + crate::retained_metadata::historical_serialization_counter_scratch_data()
            + size_of::<OriginalRestoredSuffixHostHistoricalData<'static>>()
            + size_of::<Result<OriginalRestoredSuffixHostHistoricalData<'static>, ProviderError>>()
            + size_of::<HistoricalResponse<'static>>()
            + size_of::<Option<HistoricalResponse<'static>>>()
            + size_of::<HistoricalResult<'static>>()
            + size_of::<Option<HistoricalResult<'static>>>()
            + size_of::<Option<&MethodResult>>()
            + size_of::<&MetadataRecordBank>()
            + size_of::<&mut MetadataRecordBank>()
            + size_of::<&MetadataAliasBank>()
            + size_of::<&mut MetadataAliasBank>()
            + size_of::<&'static str>()
            + size_of::<bool>()
            + size_of::<&OriginalRestoredSuffixHostAttempt>()
            + size_of::<&ResponseBody>()
            + size_of::<Option<&ResponseBody>>()
            + size_of::<&ResponseShape>()
            + size_of::<&MethodResult>()
            + size_of::<&Id>()
            + size_of::<&Option<Id>>()
            + size_of::<&Method>()
            + size_of::<&bool>()
            + size_of::<&Option<U64>>()
            + 2 * size_of::<&Option<Envelope>>()
            + size_of::<&Vec<ContentRef>>()
            + size_of::<&Option<HistoricalResponse<'static>>>()
            + size_of::<&Option<HistoricalResult<'static>>>()
            + size_of::<Result<(), ProviderError>>()
    }
}

impl Serialize for OriginalRestoredSuffixHostHistoricalData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let owner = self.original;
        let mut state = serializer.serialize_struct("RestoredSuffixHostAttempt", 11)?;
        state.serialize_field("schema", "source-private.restored-suffix-host-attempt/1")?;
        state.serialize_field("request_id", &owner.request_id)?;
        state.serialize_field("operation_id", &owner.operation_id)?;
        state.serialize_field("method", &owner.method)?;
        state.serialize_field("cut_present", &owner.cut.is_some())?;
        state.serialize_field("completed_frontier", &owner.completed_frontier)?;
        state.serialize_field("original", &owner.original)?;
        state.serialize_field("response", &owner.response)?;
        state.serialize_field("decoded", &owner.decoded.as_deref().map(HistoricalResponse))?;
        state.serialize_field("roots", &owner.roots)?;
        state.serialize_field(
            "stage",
            &match owner.stage {
                Stage::Preparing => "preparing",
                Stage::Assigned => "assigned",
                Stage::Publishing => "publishing",
                Stage::Complete => "complete",
            },
        )?;
        state.end()
    }
}

struct HistoricalResponse<'a>(&'a ResponseBody);

impl Serialize for HistoricalResponse<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("HistoricalResponseBody", 2)?;
        state.serialize_field("shape", &self.0.shape)?;
        state.serialize_field("result", &self.0.result.as_ref().map(HistoricalResult))?;
        state.end()
    }
}

struct HistoricalResult<'a>(&'a MethodResult);

fn validate_result(result: Option<&MethodResult>) -> Result<(), ProviderError> {
    match result {
        None
        | Some(
            MethodResult::BeginAccepted(_)
            | MethodResult::Poll(_)
            | MethodResult::Observe(_)
            | MethodResult::Input(_)
            | MethodResult::ExactRun(_)
            | MethodResult::BoundarySettle(_)
            | MethodResult::Retire(_)
            | MethodResult::BlobBegin(_)
            | MethodResult::BlobChunk(_)
            | MethodResult::BlobFinish(_),
        ) => Ok(()),
        Some(_) => Err(ProviderError::Correlation(
            "historical suffix typed result family differs",
        )),
    }
}

impl Serialize for HistoricalResult<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let mut state = serializer.serialize_struct("HistoricalMethodResult", 2)?;
        macro_rules! body {
            ($name:literal, $value:expr) => {{
                state.serialize_field("kind", $name)?;
                state.serialize_field("data", $value)?;
            }};
        }
        match self.0 {
            MethodResult::BeginAccepted(value) => body!("begin_accepted", value),
            MethodResult::Poll(value) => body!("poll", value),
            MethodResult::Observe(value) => body!("observe", value),
            MethodResult::Input(value) => body!("input", value),
            MethodResult::ExactRun(value) => body!("exact_run", value),
            MethodResult::BoundarySettle(value) => body!("boundary_settle", value),
            MethodResult::Retire(value) => body!("retire", value),
            MethodResult::BlobBegin(value) => body!("blob_begin", value),
            MethodResult::BlobChunk(value) => body!("blob_chunk", value),
            MethodResult::BlobFinish(value) => body!("blob_finish", value),
            _ => {
                return Err(S::Error::custom(
                    "historical suffix typed result family differs",
                ));
            }
        }
        state.end()
    }
}

impl OriginalRestoredSuffixHostAttempt {
    /// Bounds actual Bytes base64 encoding work separately from output storage.
    ///
    /// Each encoding temporary is dropped after its serialize_str call. This
    /// bound covers the largest one using the exhaustive actual capacity walk;
    /// callers independently admit serializer output, DOM and canonical banks.
    ///
    /// # Errors
    /// Refuses the metadata walk's finite bound or base64 extent overflow.
    pub fn historical_serialization_transient_bytes_data(&self) -> Result<usize, ProviderError> {
        crate::retained_metadata::historical_serialization_transient_data(
            self.retained_metadata_data()?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A rejected/unfinished DATA owner, never a Controller or Source permit.
    fn partial() -> OriginalRestoredSuffixHostAttempt {
        OriginalRestoredSuffixHostAttempt {
            request_id: Id::new("history-request").unwrap(),
            operation_id: None,
            method: Method::BlobChunk,
            controller: std::ptr::null(),
            process: 0,
            thread: std::thread::current().id(),
            cut: None,
            completed_frontier: Some(U64::new(17)),
            original: None,
            response: None,
            decoded: Some(Box::new(ResponseBody {
                shape: ResponseShape::Accepted {
                    operation_state: crate::bodies::OperationState::Running,
                    result: serde_json::Map::from_iter([(
                        "independent_raw".to_owned(),
                        serde_json::json!("unfinished"),
                    )]),
                    extensions: Extensions::new(),
                },
                result: Some(MethodResult::BlobChunk(crate::bodies::BlobChunkResult {
                    transfer_id: Id::new("independent-typed-transfer").unwrap(),
                    next_offset: U64::new(9),
                })),
            })),
            roots: Vec::with_capacity(3),
            stage: Stage::Publishing,
        }
    }

    #[test]
    fn historical_suffix_preserves_independent_failed_typed_and_raw_partials() {
        let owner = partial();
        let value = serde_json::to_value(owner.historical_data().unwrap()).unwrap();

        assert_eq!(value["stage"], "publishing");
        assert_eq!(value["completed_frontier"], "17");
        assert!(value["original"].is_null());
        assert!(value["response"].is_null());
        assert_eq!(
            value["decoded"]["shape"]["result"]["independent_raw"],
            "unfinished"
        );
        assert_eq!(value["decoded"]["result"]["kind"], "blob_chunk");
        assert_eq!(
            value["decoded"]["result"]["data"]["transfer_id"],
            "independent-typed-transfer"
        );
        for omitted in ["controller", "process", "thread", "cut"] {
            assert!(value.get(omitted).is_none());
        }
    }

    #[test]
    fn historical_suffix_recording_matches_actual_walk_and_keeps_exhausted_rows() {
        let owner = partial();
        let expected = owner.retained_metadata_data().unwrap();
        let mut records = MetadataRecordBank::reserve(expected.capacity_records).unwrap();
        let mut aliases = MetadataAliasBank::reserve(64).unwrap();
        let actual = owner
            .record_historical_metadata_data(&mut records, &mut aliases)
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(records.rows().len(), expected.capacity_records);
        let capacity = records.capacity_rows();

        let mut short = MetadataRecordBank::reserve(expected.capacity_records - 1).unwrap();
        assert!(
            owner
                .record_historical_metadata_data(&mut short, &mut aliases)
                .is_err()
        );
        assert_eq!(short.rows().len(), expected.capacity_records - 1);
        assert_eq!(owner.retained_metadata_data().unwrap(), expected);

        assert_eq!(
            owner
                .record_historical_metadata_data(&mut records, &mut aliases)
                .unwrap(),
            expected
        );
        assert_eq!(records.capacity_rows(), capacity);
        assert_eq!(records.rows().len(), expected.capacity_records);
    }
}
