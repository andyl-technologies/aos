//! Checks an inert completed SDK pair against the actual decoded Controller journal.
//!
//! The defining input is the exact eleven-field suffix-attempt history. Failed
//! and pending attempts stay in the parent's retained raw/DOM state; this lender
//! refuses their adoption rather than normalizing or discarding them. No live
//! SDK attempt, registration, operational deadline, Source seal or token exists.

use super::*;
use crate::bodies::{decode_request, decode_response};
use crate::envelope::{MessageKind, Method, RequestOrigin};
use crate::retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts};

const ATTEMPT_FIELDS: [&str; 11] = [
    "schema",
    "request_id",
    "operation_id",
    "method",
    "cut_present",
    "completed_frontier",
    "original",
    "response",
    "decoded",
    "roots",
    "stage",
];

/// Owns validated historical correspondence DATA without a live SDK conversion.
///
/// The private fields and absent Clone/Deserialize prevent a caller from
/// relabeling an arbitrary copied tuple as a validated pair. This parser result
/// carries no currentness, Source/Window grant, native receipt or execution right.
/// The enclosing reader retains the original history and immutable provenance.
pub struct ValidatedHistoricalRestoredSuffixPair {
    original: Envelope,
    terminal: Envelope,
    decoded: ResponseBody,
    frontier: U64,
}

impl ValidatedHistoricalRestoredSuffixPair {
    /// Checks complete history against the exact validated Controller17 journals.
    ///
    /// The caller independently admits the defining parser/typed temporary row
    /// before calling. Every failure leaves the parent raw/DOM history intact;
    /// temporary parsed DTOs are bounded validation work, never live SDK owners.
    ///
    /// # Errors
    /// Refuses a partial/failed stage, unknown field/family, absent saved frontier,
    /// changed request/operation/method/route, unequal raw/typed terminal or actual
    /// Controller journal identity, or a frontier beyond that Controller cut.
    pub fn validate_data(
        history: &Value,
        controller: &ValidatedControllerSettledHistory17,
    ) -> Result<Self, ProviderError> {
        validate_pair_data(history, controller.parts_data()?)
    }

    /// Borrows the exact parsed original, terminal and independent typed response.
    ///
    /// # Errors
    /// No additional failure occurs after this private DATA constructor succeeds.
    /// The Result preserves the defining live-pair adapter's borrowed signature.
    pub fn completed_pair_data(
        &self,
    ) -> Result<(&Envelope, &Envelope, &ResponseBody), ProviderError> {
        Ok((&self.original, &self.terminal, &self.decoded))
    }

    /// Returns the saved completed frontier without asserting it is still current.
    pub const fn completed_frontier_data(&self) -> U64 {
        self.frontier
    }

    /// Counts actual backing if an enclosing reader retains this inert result.
    ///
    /// The enclosing owner separately counts this type's inline header.
    ///
    /// # Errors
    /// Refuses exhaustive traversal or checked metadata/layout overflow.
    pub fn retained_metadata_data(&self) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::new();
        observer.observe(&self.original)?;
        observer.observe(&self.terminal)?;
        crate::retained_metadata::historical_response_body_data(&self.decoded)?
            .observe_retained_metadata_data(&mut observer)?;
        Ok(observer.finish())
    }
}

fn validate_pair_data(
    history: &Value,
    controller: &Value,
) -> Result<ValidatedHistoricalRestoredSuffixPair, ProviderError> {
    let history = object(history, &ATTEMPT_FIELDS)?;
    text(
        field(history, "schema")?,
        "source-private.restored-suffix-host-attempt/1",
    )?;
    text(field(history, "stage")?, "complete")?;
    if field(history, "cut_present")?.as_bool() != Some(true) {
        return Err(invalid());
    }
    let id: Id = read(field(history, "request_id")?)?;
    let operation: Option<Id> = read(field(history, "operation_id")?)?;
    let method: Method = read(field(history, "method")?)?;
    let frontier: U64 = read(field(history, "completed_frontier")?)?;
    if frontier.get() == 0 {
        return Err(invalid());
    }
    let roots: Vec<ContentRef> = read(field(history, "roots")?)?;
    for root in &roots {
        root.validate()?;
    }

    let original: Envelope = read(field(history, "original")?)?;
    let terminal: Envelope = read(field(history, "response")?)?;
    original.validate()?;
    terminal.validate()?;
    original.matches_response(&terminal)?;
    if original.message != MessageKind::Request
        || original.method != method
        || original.request_id.0.as_ref() != Some(&id)
        || original.operation_id.0 != operation
        || !matches!(
            method,
            Method::Begin
                | Method::Input
                | Method::Poll
                | Method::Retire
                | Method::Observe
                | Method::BlobBegin
                | Method::BlobChunk
                | Method::BlobFinish
        )
    {
        return Err(invalid());
    }

    let controller = controller.as_object().ok_or_else(invalid)?;
    let session = field(controller, "session")?
        .as_object()
        .ok_or_else(invalid)?;
    let current: U64 = read(field(session, "sequence")?)?;
    let node: Id = read(field(controller, "node")?)?;
    let owner: Id = read(field(controller, "execution_owner")?)?;
    if frontier <= original.sequence
        || frontier > current
        || original.node_id.0.as_ref() != Some(&node)
        || original.execution_owner_id.0.as_ref() != Some(&owner)
        || original.capture_owner_id.0.is_some()
    {
        return Err(invalid());
    }
    let custody = tuple(field(controller, "custody")?, 6)?;
    let journal = custody[3].as_object().ok_or_else(invalid)?;
    let entry = object(
        journal.get(id.as_str()).ok_or_else(invalid)?,
        &["request", "identity", "response"],
    )?;
    if field(entry, "request")? != field(history, "original")?
        || field(entry, "response")? != field(history, "response")?
    {
        return Err(invalid());
    }
    let identity: HashRef = read(field(entry, "identity")?)?;
    if original.request_hash(RequestOrigin::Controller)? != identity {
        return Err(invalid());
    }

    if matches!(method, Method::Begin | Method::Poll) != operation.is_some() {
        return Err(invalid());
    }
    let mut actual_roots = Vec::new();
    crate::client::original_suffix_response_references_data(&terminal, &mut actual_roots)?;
    if roots != actual_roots {
        return Err(invalid());
    }
    for reference in &roots {
        authenticate_content_root_data(&custody[5], reference)?;
    }

    let decoded = historical_response_data(field(history, "decoded")?)?;
    // The real suffix builder admits only these Begin kinds. Check the raw
    // discriminator before invoking its allocating selected argument decoder.
    if method == Method::Begin
        && !matches!(
            original.body.get("kind").and_then(Value::as_str),
            Some("exact_run" | "boundary_settle")
        )
    {
        return Err(invalid());
    }
    let request = decode_request(method, &original.body)?;
    if matches!(
        &request,
        RequestBody::Begin(body)
            if !matches!(body.kind, BeginKind::ExactRun | BeginKind::BoundarySettle)
    ) {
        return Err(invalid());
    }
    if decode_response(&request, &terminal.body)? != decoded {
        return Err(invalid());
    }
    Ok(ValidatedHistoricalRestoredSuffixPair {
        original,
        terminal,
        decoded,
        frontier,
    })
}

fn historical_response_data(value: &Value) -> Result<ResponseBody, ProviderError> {
    let value = object(value, &["shape", "result"])?;
    let shape: ResponseShape = read(field(value, "shape")?)?;
    let result = field(value, "result")?;
    let result = if result.is_null() {
        None
    } else {
        let value = object(result, &["kind", "data"])?;
        let data = field(value, "data")?;
        Some(match field(value, "kind")?.as_str() {
            Some("begin_accepted") => MethodResult::BeginAccepted(read(data)?),
            Some("poll") => MethodResult::Poll(read(data)?),
            Some("observe") => MethodResult::Observe(read(data)?),
            Some("input") => MethodResult::Input(read(data)?),
            Some("exact_run") => MethodResult::ExactRun(read(data)?),
            Some("boundary_settle") => MethodResult::BoundarySettle(read(data)?),
            Some("retire") => MethodResult::Retire(read(data)?),
            Some("blob_begin") => MethodResult::BlobBegin(read(data)?),
            Some("blob_chunk") => MethodResult::BlobChunk(read(data)?),
            Some("blob_finish") => MethodResult::BlobFinish(read(data)?),
            _ => return Err(invalid()),
        })
    };
    Ok(ResponseBody { shape, result })
}

/// Quotes independent temporary ownership for one historical pair validation.
///
/// This includes typed pair results if retained during later B checks. A caller
/// keeping multiple pairs simultaneously multiplies this row by that actual
/// count. Parent raw/DOM owners and B's own decoder work remain independent.
///
/// # Errors
/// Refuses zero/overflowing encoded geometry. The result grants no admission.
pub fn historical_restored_suffix_pair_validation_transient_bytes_data(
    maximum_encoded: usize,
) -> Result<usize, ProviderError> {
    let extent =
        crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data(
            maximum_encoded,
        )?;
    let typed = extent
        .maximum_value_nodes
        .checked_mul(pair_element_layouts())
        .ok_or_else(invalid)?;
    extent
        .canonical_pass_requested_bytes()?
        .checked_mul(4)
        .and_then(|value| value.checked_add(typed))
        .and_then(|value| value.checked_add(historical_restored_suffix_pair_counter_scratch_data()))
        .ok_or_else(invalid)
}

fn pair_element_layouts() -> usize {
    request_element_layouts()
        + size_of::<Envelope>()
        + size_of::<ResponseBody>()
        + size_of::<MethodResult>()
        + size_of::<ContentRef>()
        + size_of::<Id>()
        + size_of::<String>()
        + size_of::<crucible_node_contract::ObservationBatch>()
        + size_of::<crucible_node_contract::Event>()
}

// The strict parent already validated the full content8 byte/reference/hash
// graph. This defining shape check lends its completed object membership only;
// it does not reparse/rebuild that potentially much larger byte bank here.
pub(super) fn authenticate_content_root_data(
    content: &Value,
    reference: &ContentRef,
) -> Result<(), ProviderError> {
    let wrapper = tuple(content, 4)?;
    text(&wrapper[0], "source-private.client-content/8")?;
    let content = tuple(&wrapper[1], 7)?;
    text(&content[0], "source-private.client-content/7")?;
    for object in content[6].as_array().ok_or_else(invalid)? {
        let object = tuple(object, 5)?;
        if object[0].as_str() == Some(reference.hash.digest.as_str()) {
            let actual: ContentRef = read(&object[1])?;
            return if actual == *reference {
                Ok(())
            } else {
                Err(invalid())
            };
        }
    }
    Err(invalid())
}

fn request_element_layouts() -> usize {
    size_of::<RequestBody>()
        + size_of::<BeginRequest>()
        + size_of::<BeginArguments>()
        + size_of::<ExactRunArguments>()
        + size_of::<InputRequest>()
        + size_of::<crucible_node_contract::Event>()
        + size_of::<ObserveRequest>()
        + size_of::<PollRequest>()
        + size_of::<RetireRequest>()
        + size_of::<BlobBeginRequest>()
        + size_of::<BlobChunkRequest>()
        + size_of::<BlobFinishRequest>()
        + size_of::<crucible_node_contract::Bytes>()
}

/// Names the actual strict historical pair, typed results and metadata views.
pub fn historical_restored_suffix_pair_counter_scratch_data() -> usize {
    typed_field_counter_views::<RequestBody>()
        + typed_field_counter_views::<BeginRequest>()
        + typed_field_counter_views::<BeginArguments>()
        + typed_field_counter_views::<ExactRunArguments>()
        + typed_field_counter_views::<InputRequest>()
        + typed_field_counter_views::<ObserveRequest>()
        + typed_field_counter_views::<PollRequest>()
        + typed_field_counter_views::<RetireRequest>()
        + typed_field_counter_views::<BlobBeginRequest>()
        + typed_field_counter_views::<BlobChunkRequest>()
        + typed_field_counter_views::<BlobFinishRequest>()
        + crate::client::original_suffix_response_references_counter_scratch_data()
        + typed_field_counter_views::<ContentRef>()
        + size_of::<Vec<ContentRef>>()
        + size_of::<&mut Vec<ContentRef>>()
        + size_of::<Result<BeginArguments, crucible_node_contract::ContractError>>()
        + size_of::<Result<ExactRunArguments, serde_json::Error>>()
        + size_of::<Result<InputRequest, serde_json::Error>>()
        + size_of::<Result<RequestBody, ProviderError>>()
        + size_of::<Option<&str>>()
        + size_of::<[&str;7]>()
        + size_of::<&ValidatedControllerSettledHistory17>()
        + size_of::<&Value>() * 3
        + size_of::<&Map<String, Value>>()
        + size_of::<&[Value]>()
        + size_of::<&[&str]>()
        + size_of::<&str>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<Result<&Value, ProviderError>>()
        + size_of::<Result<&Map<String, Value>, ProviderError>>()
        + size_of::<Result<&[Value], ProviderError>>()
        + size_of::<Option<&Id>>()
        + size_of::<Option<&Value>>()
        + size_of::<bool>()
        + size_of::<Result<(), crucible_node_contract::ContractError>>()
        + typed_field_counter_views::<Envelope>()
        + typed_field_counter_views::<Id>()
        + typed_field_counter_views::<Option<Id>>()
        + typed_field_counter_views::<Method>()
        + typed_field_counter_views::<U64>()
        + typed_field_counter_views::<HashRef>()
        + typed_field_counter_views::<Vec<ContentRef>>()
        + typed_field_counter_views::<ResponseShape>()
        + typed_field_counter_views::<BeginAccepted>()
        + typed_field_counter_views::<PollResult>()
        + typed_field_counter_views::<ObserveResult>()
        + typed_field_counter_views::<InputResult>()
        + typed_field_counter_views::<ExactRunResult>()
        + typed_field_counter_views::<RetireResult>()
        + typed_field_counter_views::<BlobBeginResult>()
        + typed_field_counter_views::<BlobChunkResult>()
        + typed_field_counter_views::<BlobFinishResult>()
        + size_of::<ValidatedHistoricalRestoredSuffixPair>()
        + size_of::<&ValidatedHistoricalRestoredSuffixPair>()
        + size_of::<Result<ValidatedHistoricalRestoredSuffixPair, ProviderError>>()
        + size_of::<[&str;11]>()
        + size_of::<[&str;3]>()
        + size_of::<[&str;2]>()
        + size_of::<(&Envelope, &Envelope, &ResponseBody)>()
        + size_of::<Result<(&Envelope, &Envelope, &ResponseBody), ProviderError>>()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<ResponseBody, ProviderError>>()
        + size_of::<Result<crate::bodies::RequestBody, ProviderError>>()
        + size_of::<Result<Envelope, ProviderError>>()
        + size_of::<Result<Id, ProviderError>>()
        + size_of::<Result<Option<Id>, ProviderError>>()
        + size_of::<Option<Id>>()
        + size_of::<Result<Method, ProviderError>>()
        + size_of::<Result<U64, ProviderError>>()
        + size_of::<Result<HashRef, ProviderError>>()
        + size_of::<Result<Vec<ContentRef>, ProviderError>>()
        + size_of::<Result<ResponseShape, ProviderError>>()
        + size_of::<Option<MethodResult>>()
        + size_of::<std::slice::Iter<'static, ContentRef>>()
        + size_of::<Result<crate::bodies::BeginAccepted, ProviderError>>()
        + size_of::<Result<crate::bodies::PollResult, ProviderError>>()
        + size_of::<Result<crate::bodies::ObserveResult, ProviderError>>()
        + size_of::<Result<crate::bodies::InputResult, ProviderError>>()
        + size_of::<Result<crate::bodies::ExactRunResult, ProviderError>>()
        + size_of::<Result<crate::bodies::RetireResult, ProviderError>>()
        + size_of::<Result<crate::bodies::BlobBeginResult, ProviderError>>()
        + size_of::<Result<crate::bodies::BlobChunkResult, ProviderError>>()
        + size_of::<Result<crate::bodies::BlobFinishResult, ProviderError>>()
        + crate::retained_metadata::historical_response_body_counter_scratch_data()
        + crate::retained_metadata::serialization_storage::original_json_value_storage_extent_counter_scratch_data()
        + pair_element_layouts()
}

fn typed_field_counter_views<T>() -> usize {
    size_of::<T>()
        + size_of::<&T>()
        + size_of::<Result<T, ProviderError>>()
        + size_of::<Result<T, serde_json::Error>>()
        + size_of::<Result<T, crucible_node_contract::ContractError>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Nullable;
    use crucible_node_contract::{Bytes, Extensions};
    use serde_json::json;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn historical_values() -> Result<(Value, Value), Box<dyn std::error::Error>> {
        let id = |value: &str| Id::new(value);
        let body = serde_json::to_value(BlobChunkRequest {
            transfer_id: id("pair-transfer")?,
            offset: U64::new(0),
            bytes: Bytes::new(vec![1, 2, 3]),
            extensions: Extensions::new(),
        })?;
        let original = Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(id("pair-session")?)),
            incarnation_id: Nullable(Some(id("pair-incarnation")?)),
            node_id: Nullable(Some(id("pair-node")?)),
            execution_owner_id: Nullable(Some(id("pair-owner")?)),
            capture_owner_id: Nullable(None),
            request_id: Nullable(Some(id("pair-request")?)),
            operation_id: Nullable(None),
            sequence: U64::new(1),
            method: Method::BlobChunk,
            body: body.as_object().ok_or_else(invalid)?.clone(),
            extensions: Extensions::new(),
        };
        let result = serde_json::to_value(BlobChunkResult {
            transfer_id: id("pair-transfer")?,
            next_offset: U64::new(3),
        })?;
        let body = serde_json::to_value(ResponseShape::Completed {
            operation_state: OperationState::Completed,
            result: result.as_object().ok_or_else(invalid)?.clone(),
            extensions: Extensions::new(),
        })?;
        let mut terminal = original.clone();
        terminal.message = MessageKind::Response;
        terminal.body = body.as_object().ok_or_else(invalid)?.clone();
        let typed = decode_response(
            &decode_request(original.method, &original.body)?,
            &terminal.body,
        )?;
        let decoded = crate::retained_metadata::historical_response_body_data(&typed)?;
        let history = json!({
            "schema":"source-private.restored-suffix-host-attempt/1","request_id":"pair-request","operation_id":null,"method":"blob_chunk",
            "cut_present":true,"completed_frontier":"2","original":original,"response":terminal,"decoded":decoded,"roots":[],"stage":"complete",
        });
        // Only the private relational helper consumes this inert test fragment;
        // it is deliberately not a forged ValidatedController17 or live owner.
        let controller = json!({
            "node":"pair-node",
            "execution_owner":"pair-owner",
            "session":{"sequence":"2"},
            "custody":[
                64,65536,0,
                {"pair-request":{
                    "request":original,
                    "identity":original.request_hash(RequestOrigin::Controller)?,
                    "response":terminal
                }},
                {},
                ["source-private.client-content/8",
                    ["source-private.client-content/7",65536,64,4096,0,[],[]],
                    [],[]]
            ]
        });
        Ok((history, controller))
    }

    #[test]
    fn strict_pair_rejects_independent_typed_and_actual_journal_tampering() -> TestResult {
        let (history, controller) = historical_values()?;
        let pair = validate_pair_data(&history, &controller)?;
        assert_eq!(pair.completed_frontier_data(), U64::new(2));
        assert_eq!(
            pair.completed_pair_data()?
                .0
                .request_id
                .0
                .as_ref()
                .map(Id::as_str),
            Some("pair-request")
        );

        let mut wrong_typed = history.clone();
        wrong_typed["decoded"]["result"]["data"]["transfer_id"] = json!("another-transfer");
        assert!(validate_pair_data(&wrong_typed, &controller).is_err());
        let mut wrong_journal = controller.clone();
        wrong_journal["custody"][3]["pair-request"]["identity"]["digest"] = json!("0".repeat(64));
        assert!(validate_pair_data(&history, &wrong_journal).is_err());
        Ok(())
    }

    #[test]
    fn strict_pair_preserves_but_refuses_pending_or_future_frontier_history() -> TestResult {
        let (mut history, controller) = historical_values()?;
        history["stage"] = json!("publishing");
        let retained = history.clone();
        assert!(validate_pair_data(&history, &controller).is_err());
        assert_eq!(history, retained);

        history["stage"] = json!("complete");
        history["completed_frontier"] = json!("3");
        assert!(validate_pair_data(&history, &controller).is_err());
        Ok(())
    }

    #[test]
    fn strict_pair_requires_frontier_after_original_and_exact_response_roots() -> TestResult {
        let (mut history, mut controller) = historical_values()?;
        history["original"]["sequence"] = json!("10");
        controller["custody"][3]["pair-request"]["request"]["sequence"] = json!("10");
        controller["session"]["sequence"] = json!("20");
        history["completed_frontier"] = json!("11");
        assert!(validate_pair_data(&history, &controller).is_ok());

        history["completed_frontier"] = json!("2");
        assert!(validate_pair_data(&history, &controller).is_err());

        let (mut history, controller) = historical_values()?;
        history["roots"] = json!([crucible_node_contract::canonical::content_ref(
            b"unexpected",
            "application/json"
        )?]);
        assert!(validate_pair_data(&history, &controller).is_err());
        Ok(())
    }

    #[test]
    fn strict_pair_requires_promised_root_in_verified_controller_objects() -> TestResult {
        let (mut history, mut controller) = historical_values()?;
        let reference =
            crucible_node_contract::canonical::content_ref(b"result", "application/json")?;
        let original: Envelope = read(&history["original"])?;
        let mut original = original;
        original.method = Method::BlobFinish;
        original.body = serde_json::to_value(BlobFinishRequest {
            transfer_id: Id::new("pair-transfer")?,
            extensions: Extensions::new(),
        })?
        .as_object()
        .ok_or_else(invalid)?
        .clone();
        let mut terminal = original.clone();
        terminal.message = MessageKind::Response;
        terminal.body = serde_json::to_value(ResponseShape::Completed {
            operation_state: OperationState::Completed,
            result: serde_json::to_value(BlobFinishResult {
                transfer_id: Id::new("pair-transfer")?,
                content: reference.clone(),
            })?
            .as_object()
            .ok_or_else(invalid)?
            .clone(),
            extensions: Extensions::new(),
        })?
        .as_object()
        .ok_or_else(invalid)?
        .clone();
        let typed = decode_response(
            &decode_request(original.method, &original.body)?,
            &terminal.body,
        )?;
        history["method"] = json!("blob_finish");
        history["original"] = serde_json::to_value(&original)?;
        history["response"] = serde_json::to_value(&terminal)?;
        history["decoded"] = serde_json::to_value(
            crate::retained_metadata::historical_response_body_data(&typed)?,
        )?;
        controller["custody"][3]["pair-request"] = json!({
            "request":original,
            "identity":original.request_hash(RequestOrigin::Controller)?,
            "response":terminal
        });

        // The defining traversal finds this root in the actual raw response.
        // Omission and a promised but absent content object each refuse.
        assert!(validate_pair_data(&history, &controller).is_err());
        history["roots"] = json!([reference]);
        assert!(validate_pair_data(&history, &controller).is_err());
        Ok(())
    }
}
