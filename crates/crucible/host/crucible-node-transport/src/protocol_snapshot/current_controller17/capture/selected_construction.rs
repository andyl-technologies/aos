//! Quotes SDK Capture constructor work from actual borrowed selected shapes.
//!
//! The returned SDK owner has an independent retained row. This row covers
//! fixed Capture/confirmation work plus the largest sequential upload window.
//! No DTO, validator, custom Bytes formatter, Value clone or bank is constructed.

use super::*;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection,
    original_serialization_tree_node_requested_bytes_data,
};

// This pinned serde buffer backs internally tagged ResponseShape decoding.
type SerdeContent = serde::__private228::de::Content<'static>;

const CAPTURE_FIELDS: [&str; 15] = [
    "body",
    "request",
    "arguments",
    "unsigned_request",
    "original",
    "context",
    "artifact",
    "terminal",
    "decoded",
    "roots",
    "confirmation",
    "request_id",
    "operation_id",
    "capture_frontier",
    "prefix_frontier",
];
const UPLOAD_FIELDS: [&str; 5] = [
    "request",
    "context",
    "artifact",
    "next_offset",
    "maximum_chunk",
];
const ROW_FIELDS: [&str; 8] = [
    "body",
    "continuation",
    "extension",
    "original",
    "terminal",
    "decoded",
    "request_id",
    "frontier",
];

/// Quotes transient SDK validation from an actual opaque Controller owner.
///
/// The returned SDK history remains covered by its separate retained quote.
/// This row prices selected Capture/confirmation shapes and the greatest upload
/// header/original window. Upload originals are checked sequentially and their
/// payloads are streamed; unrelated Controller history and the sum of all chunks
/// do not become simultaneous typed SDK copies.
///
/// Borrowed structural checks select only the completed reader's actual method
/// families and empty final Poll observations before choosing its array roster.
/// They authenticate nothing. Full validation and Source admission are separate.
/// The existing byte-extent helper retains its original meaning.
///
/// # Errors
/// Refuses unavailable selected fields, another method/result family, excessive
/// nesting, checked overflow, or a quote greater than `maximum`. This DATA does
/// not grant construction or effect authority.
pub fn historical_restored_settled_capture17_selected_validation_transient_bytes_data(
    controller: &ValidatedControllerSettledHistory17,
    maximum: usize,
) -> Result<usize, ProviderError> {
    let root = controller.parts_data()?.as_object().ok_or_else(invalid)?;
    selected_work_data(root, maximum)
}

/// Quotes the independent returned SDK owner from its actual selected fields.
///
/// The eleven returned owner subtrees supply their own String, Value and tree
/// backing. Three participant Id vectors and the Capture result's ContentRef
/// vector use their actual typed slots. The root header and canonical-original
/// byte bank are separate terms. Upload payloads and serde Content buffers are
/// not retained by this output; validation T and earlier SDK loans stay separate.
///
/// The caller admits the selected-counter scratch before this borrowed walk.
/// No DTO is decoded and no live or historical authenticity is inferred.
///
/// # Errors
/// Refuses missing or unsupported selected fields, a non-byte canonical bank,
/// checked overflow, or demand exceeding `maximum`. It grants no allocation.
pub fn historical_restored_settled_capture17_selected_retained_construction_bytes_data(
    controller: &ValidatedControllerSettledHistory17,
    maximum: usize,
) -> Result<usize, ProviderError> {
    let root = controller.parts_data()?.as_object().ok_or_else(invalid)?;
    selected_retained_data(root, maximum)
}

fn selected_retained_data(
    root: &Map<String, Value>,
    maximum: usize,
) -> Result<usize, ProviderError> {
    let capture = field(root, "capture")?.as_object().ok_or_else(invalid)?;
    let confirmation = field(capture, "confirmation")?
        .as_object()
        .ok_or_else(invalid)?;
    pair_family_data(capture, "begin", "capture")?;
    pair_family_data(confirmation, "poll", "poll")?;
    let terminal_body = field(envelope_data(confirmation, "terminal")?, "body")?
        .as_object()
        .ok_or_else(invalid)?;
    empty_observations_data(field(terminal_body, "result")?)?;
    let confirmation_result = field(confirmation, "decoded")?
        .as_object()
        .ok_or_else(invalid)?;
    let confirmation_result = field(confirmation_result, "result")?
        .as_object()
        .ok_or_else(invalid)?;
    empty_observations_data(field(confirmation_result, "data")?)?;

    let fields = [
        field(capture, "original")?,
        field(capture, "terminal")?,
        field(capture, "decoded")?,
        field(capture, "request")?,
        field(capture, "context")?,
        field(capture, "artifact")?,
        field(confirmation, "original")?,
        field(confirmation, "terminal")?,
        field(confirmation, "decoded")?,
        field(confirmation, "request")?,
        field(confirmation, "receipt")?,
    ];
    let mut retained = size_of::<ValidatedHistoricalRestoredSettledCapture17>();
    for value in fields {
        // Root field headers are already inside the actual SDK header above.
        // Bound only backing here; no canonical/parser work or tagged Content
        // belongs to the output's retained row.
        retained = add_data(retained, retained_backing_data(value, 0)?)?;
    }

    for request in [
        field(capture, "request")?,
        field(
            field(capture, "context")?.as_object().ok_or_else(invalid)?,
            "request",
        )?,
        field(
            field(capture, "artifact")?
                .as_object()
                .ok_or_else(invalid)?,
            "request",
        )?,
    ] {
        let request = request.as_object().ok_or_else(invalid)?;
        let arguments = field(request, "capture")?.as_object().ok_or_else(invalid)?;
        let participants = field(arguments, "participant_ids")?
            .as_array()
            .ok_or_else(invalid)?;
        retained = add_data(retained, grow_data(participants.len(), size_of::<Id>())?)?;
    }
    let decoded = field(capture, "decoded")?.as_object().ok_or_else(invalid)?;
    let result = field(decoded, "result")?.as_object().ok_or_else(invalid)?;
    let result = field(result, "data")?.as_object().ok_or_else(invalid)?;
    let owners = field(result, "owner_state_refs")?
        .as_array()
        .ok_or_else(invalid)?;
    retained = add_data(retained, grow_data(owners.len(), size_of::<ContentRef>())?)?;

    let canonical = field(capture, "canonical")?
        .as_array()
        .ok_or_else(invalid)?;
    for byte in canonical {
        if byte.as_u64().and_then(|n| u8::try_from(n).ok()).is_none() {
            return Err(invalid());
        }
    }
    retained = add_data(retained, grow_data(canonical.len(), size_of::<u8>())?)?;
    if retained > maximum {
        return Err(exhausted());
    }
    Ok(retained)
}

fn retained_backing_data(value: &Value, depth: usize) -> Result<usize, ProviderError> {
    if depth >= 64 {
        return Err(exhausted());
    }
    match value {
        Value::String(text) => grow_data(text.len(), size_of::<u8>()),
        Value::Array(values) => {
            let bank = grow_data(values.len(), size_of::<Value>())?;
            values.iter().try_fold(bank, |sum, value| {
                add_data(sum, retained_backing_data(value, depth + 1)?)
            })
        }
        Value::Object(fields) => {
            let nodes = fields.len().checked_add(1).ok_or_else(exhausted)?;
            let bank = nodes
                .checked_mul(original_serialization_tree_node_requested_bytes_data::<
                    String,
                    Value,
                >()?)
                .ok_or_else(exhausted)?;
            fields.iter().try_fold(bank, |sum, (key, value)| {
                add_data(
                    add_data(sum, grow_data(key.len(), size_of::<u8>())?)?,
                    retained_backing_data(value, depth + 1)?,
                )
            })
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(0),
    }
}

fn selected_work_data(root: &Map<String, Value>, maximum: usize) -> Result<usize, ProviderError> {
    let history = field(root, "capture")?.as_object().ok_or_else(invalid)?;
    pair_family_data(history, "begin", "capture")?;
    capture_body_data(field(history, "body")?)?;
    capture_body_data(field(envelope_data(history, "original")?, "body")?)?;

    let confirmation = field(history, "confirmation")?
        .as_object()
        .ok_or_else(invalid)?;
    pair_family_data(confirmation, "poll", "poll")?;
    let terminal_body = field(envelope_data(confirmation, "terminal")?, "body")?
        .as_object()
        .ok_or_else(invalid)?;
    empty_observations_data(field(terminal_body, "result")?)?;
    let decoded = field(confirmation, "decoded")?
        .as_object()
        .ok_or_else(invalid)?;
    let result = field(decoded, "result")?.as_object().ok_or_else(invalid)?;
    empty_observations_data(field(result, "data")?)?;

    let fixed = fields_work_data(history, &CAPTURE_FIELDS, maximum)?;
    // The grammar pass constructs and drops a Vec<u8> before the main reader
    // retains canonical_original under its independent retained-construction row.
    let canonical = field(history, "canonical")?
        .as_array()
        .ok_or_else(invalid)?;
    let canonical_bank = grow_data(canonical.len(), size_of::<u8>())?;
    let identities = add_data(
        identity_work_data(history, root, maximum)?,
        identity_work_data(confirmation, root, maximum)?,
    )?;
    let content_reference_peak = content_reference_peak_data(root, maximum)?;
    let terminal_body = field(envelope_data(history, "terminal")?, "body")?;
    let collected_roots = grow_data(
        reference_count_data(terminal_body)?,
        size_of::<ContentRef>(),
    )?;

    let mut upload_peak = 0usize;
    for upload in tuple(field(history, "auxiliary_uploads")?, 2)? {
        let upload = upload.as_object().ok_or_else(invalid)?;
        let headers = fields_work_data(upload, &UPLOAD_FIELDS, maximum)?;
        let completed = field(upload, "completed")?.as_array().ok_or_else(invalid)?;
        if !field(upload, "pending")?.is_null() || completed.len() < 2 {
            return Err(invalid());
        }
        let mut row_peak = 0usize;
        for (index, row) in completed.iter().enumerate() {
            let row = row.as_object().ok_or_else(invalid)?;
            let kind = if index == 0 {
                "blob_begin"
            } else if index + 1 == completed.len() {
                "blob_finish"
            } else {
                "blob_chunk"
            };
            pair_family_data(row, kind, kind)?;
            row_peak = row_peak.max(add_data(
                fields_work_data(row, &ROW_FIELDS, maximum)?,
                identity_work_data(row, root, maximum)?,
            )?);
        }
        upload_peak = upload_peak.max(add_data(headers, row_peak)?);
    }

    // pair_data parses these independent route values even when a selected
    // request contains adversarially different strings.
    let session = field(root, "session")?.as_object().ok_or_else(invalid)?;
    let authority = field(session, "authority")?
        .as_object()
        .ok_or_else(invalid)?;
    let routes = add_data(
        fields_work_data(root, &["node", "execution_owner"], maximum)?,
        add_data(
            fields_work_data(session, &["sequence"], maximum)?,
            fields_work_data(authority, &["session", "incarnation", "limits"], maximum)?,
        )?,
    )?;
    let scratch = add_data(
        historical_restored_settled_capture17_counter_scratch_data(),
        add_data(
            super::super::super::current_sdk_capture17::counter_scratch_data(),
            historical_restored_settled_capture17_selected_counter_scratch_data(),
        )?,
    )?;
    let total = [
        fixed,
        canonical_bank,
        identities,
        content_reference_peak,
        collected_roots,
        upload_peak,
        routes,
        scratch,
    ]
    .into_iter()
    .try_fold(0, add_data)?;
    if total > maximum {
        return Err(exhausted());
    }
    Ok(total)
}

fn pair_family_data(
    history: &Map<String, Value>,
    method: &str,
    result_kind: &str,
) -> Result<(), ProviderError> {
    text(field(history, "stage")?, "complete")?;
    text(
        field(envelope_data(history, "original")?, "method")?,
        method,
    )?;
    text(
        field(envelope_data(history, "terminal")?, "method")?,
        method,
    )?;
    let decoded = field(history, "decoded")?.as_object().ok_or_else(invalid)?;
    let result = field(decoded, "result")?.as_object().ok_or_else(invalid)?;
    text(field(result, "kind")?, result_kind)
}

fn envelope_data<'a>(
    history: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a Map<String, Value>, ProviderError> {
    field(history, name)?.as_object().ok_or_else(invalid)
}

fn capture_body_data(body: &Value) -> Result<(), ProviderError> {
    text(
        field(body.as_object().ok_or_else(invalid)?, "kind")?,
        "capture",
    )
}

fn empty_observations_data(result: &Value) -> Result<(), ProviderError> {
    let result = result.as_object().ok_or_else(invalid)?;
    if !field(result, "observations")?
        .as_array()
        .ok_or_else(invalid)?
        .is_empty()
    {
        return Err(invalid());
    }
    Ok(())
}

fn identity_work_data(
    history: &Map<String, Value>,
    root: &Map<String, Value>,
    maximum: usize,
) -> Result<usize, ProviderError> {
    let id = field(history, "request_id")?.as_str().ok_or_else(invalid)?;
    let custody = tuple(field(root, "custody")?, 6)?;
    let journal = custody[3].as_object().ok_or_else(invalid)?;
    let entry = journal
        .get(id)
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    fields_work_data(entry, &["identity"], maximum)
}

fn content_reference_peak_data(
    root: &Map<String, Value>,
    maximum: usize,
) -> Result<usize, ProviderError> {
    let custody = tuple(field(root, "custody")?, 6)?;
    let wrapper = tuple(&custody[5], 4)?;
    let content = tuple(&wrapper[1], 7)?;
    let mut peak = 0usize;
    // Membership deserializes only a matching dictionary reference. Include
    // the greatest actual reference even if it disagrees with the requested one;
    // payload bytes and the rest of the dictionary are merely borrowed.
    for object in content[6].as_array().ok_or_else(invalid)? {
        let object = tuple(object, 5)?;
        peak = peak.max(value_work_data(&object[1], maximum)?);
    }
    Ok(peak)
}

fn reference_count_data(value: &Value) -> Result<usize, ProviderError> {
    match value {
        Value::Object(fields)
            if fields.contains_key("hash")
                && fields.contains_key("length")
                && fields.contains_key("media_type") =>
        {
            Ok(1)
        }
        Value::Object(fields) => fields
            .values()
            .try_fold(0, |sum, value| add_data(sum, reference_count_data(value)?)),
        Value::Array(values) => values
            .iter()
            .try_fold(0, |sum, value| add_data(sum, reference_count_data(value)?)),
        _ => Ok(0),
    }
}

fn fields_work_data(
    fields: &Map<String, Value>,
    names: &[&str],
    maximum: usize,
) -> Result<usize, ProviderError> {
    let mut projection = OriginalSerializationStorageProjection::new(maximum)?;
    let mut typed = 0usize;
    projection.add_object()?;
    for name in names {
        let value = field(fields, name)?;
        projection.add_field(name)?;
        // Value's borrowed serializer cannot invoke contract Bytes/U64 formatters.
        projection.add_value(value)?;
        typed = add_data(typed, typed_backing_data(value, 0)?)?;
    }
    pools_data(projection, typed, maximum)
}

fn value_work_data(value: &Value, maximum: usize) -> Result<usize, ProviderError> {
    let mut projection = OriginalSerializationStorageProjection::new(maximum)?;
    projection.add_value(value)?;
    pools_data(projection, typed_backing_data(value, 0)?, maximum)
}

fn pools_data(
    projection: OriginalSerializationStorageProjection,
    typed: usize,
    maximum: usize,
) -> Result<usize, ProviderError> {
    let storage = projection.finish(maximum)?;

    // Two Value/canonical pools cover request_hash's projection and json_hash's
    // second Value, or a body decoder's saved canonical bank alongside its clone.
    // Three typed pools cover current DTO backing, tagged-content buffering and
    // independent normalizer/continuation copies. Every selected field is summed
    // although these constructors run sequentially. String pools additionally
    // cover one Bytes/base64 formatter and cloned validation sort keys.
    add_data(
        storage
            .requested_total()?
            .checked_mul(2)
            .ok_or_else(exhausted)?,
        typed.checked_mul(3).ok_or_else(exhausted)?,
    )
}

fn typed_backing_data(value: &Value, depth: usize) -> Result<usize, ProviderError> {
    if depth >= 64 {
        return Err(exhausted());
    }
    match value {
        Value::String(text) => grow_data(text.len(), size_of::<u8>()),
        Value::Array(values) => {
            let slots = grow_data(values.len(), maximum_array_element_data())?;
            values.iter().try_fold(slots, |sum, value| {
                add_data(sum, typed_backing_data(value, depth + 1)?)
            })
        }
        Value::Object(fields) => {
            let nodes = fields.len().checked_add(1).ok_or_else(exhausted)?;
            let tree = nodes
                .checked_mul(original_serialization_tree_node_requested_bytes_data::<
                    String,
                    Value,
                >()?)
                .ok_or_else(exhausted)?;
            let tagged = grow_data(fields.len(), size_of::<(SerdeContent, SerdeContent)>())?;
            fields
                .iter()
                .try_fold(add_data(tree, tagged)?, |sum, (key, value)| {
                    add_data(
                        add_data(sum, grow_data(key.len(), size_of::<u8>())?)?,
                        typed_backing_data(value, depth + 1)?,
                    )
                })
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(0),
    }
}

fn maximum_array_element_data() -> usize {
    [
        size_of::<u8>(),
        size_of::<Id>(),
        size_of::<ContentRef>(),
        size_of::<Value>(),
        size_of::<SerdeContent>(),
        size_of::<(SerdeContent, SerdeContent)>(),
    ]
    .into_iter()
    .max()
    .unwrap_or(0)
}

/// Names the selected geometry counter's fixed explicit work views.
///
/// Callers admit this scratch before invoking the borrowed geometry walk. The
/// hard JSON-depth bound names its repeated recursive controls; this reports
/// neither compiler frames nor allocation authority. The returned T quote also
/// contains this term, so retaining it on both axes is conservative.
pub fn historical_restored_settled_capture17_selected_counter_scratch_data() -> usize {
    // Explicit views of this nonallocating counter, with its existing hard
    // JSON-depth bound. Compiler frames/allocator overhead are not inferred.
    size_of::<OriginalSerializationStorageProjection>()
        + size_of::<OriginalSerializationStorageData>()
        + size_of::<Result<OriginalSerializationStorageData, ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<SerdeContent>() * 2
        + size_of::<Vec<SerdeContent>>()
        + size_of::<Vec<(SerdeContent, SerdeContent)>>()
        + size_of::<[usize; 8]>()
        + size_of::<[usize; 6]>()
        + size_of::<[&Value; 11]>()
        + size_of::<[&Value; 3]>()
        + size_of::<[&Map<String, Value>; 8]>()
        + 64 * (size_of::<std::slice::Iter<'static, Value>>()
            + size_of::<serde_json::map::Iter<'static>>()
            + size_of::<(&str, &Value)>()
            + size_of::<usize>() * 4)
        + crate::retained_metadata::serialization_storage::
            original_serialization_tree_node_counter_scratch_data()
}

fn grow_data(count: usize, element: usize) -> Result<usize, ProviderError> {
    count
        .checked_mul(4)
        .and_then(|n| n.checked_add(32))
        .and_then(|n| n.checked_mul(element))
        .ok_or_else(exhausted)
}

fn add_data(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(exhausted)
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("selected SDK Capture construction")
}

#[cfg(test)]
#[path = "selected_construction_tests.rs"]
mod tests;
