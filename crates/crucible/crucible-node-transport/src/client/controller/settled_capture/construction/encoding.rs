//! Prices additional serialized SDK/journal ownership after completed Capture.
//!
//! These field rosters mirror settled_capture/history.rs and ClientOriginal.
//! Generic journals use the canonical expansion of the negotiated raw frame.
//! Successful closed SDK envelopes retain their separate frame bounds. Standalone
//! request/context/artifact/continuation DTOs satisfy their defining artifact
//! caps before successful completion; their heap backing is not an encoding cap.

use super::*;
use crate::client::history_encoding17 as json;

pub(super) fn sdk_history_data(
    frame: usize,
    auxiliary: [usize; 2],
) -> Result<usize, ProviderError> {
    let artifact = MAXIMUM_RESTORED_SETTLED_CAPTURE_ARTIFACT_BYTES;
    let id = json::string(128)?;
    let mut uploads = 2usize;
    for originals in auxiliary {
        let original = auxiliary_original_data(frame)?;
        let completed = json::array(originals, original)?;
        let upload = json::object(&[
            ("request", artifact),
            ("context", artifact),
            ("artifact", artifact),
            ("pending", 4),
            ("completed", completed),
            ("next_offset", json::U64_STRING),
            ("maximum_chunk", json::U64_STRING),
            ("finished", 4),
            ("maximum_originals", json::DECIMAL),
        ])?;
        uploads = json::add(uploads, json::add(upload, 1)?)?;
    }
    let confirmation = json::object(&[
        ("request_id", id),
        ("request", frame),
        ("extension", frame),
        ("original", frame),
        ("cut_present", 4),
        ("terminal", frame),
        ("decoded", response_data(frame, "poll")?),
        ("receipt", frame),
        ("roots", 2),
        ("frontier", json::U64_STRING),
        ("stage", json::literal("complete")?),
    ])?;
    // references() stops at each ContentRef candidate and de-duplicates it.
    // The successful roots' disjoint source subtrees therefore fit one raw
    // terminal frame plus array brackets, without a count×reference guess.
    let roots = json::add(frame, 2)?;
    json::object(&[
        (
            "schema",
            json::literal("source-private.restored-settled-capture-sdk/17")?,
        ),
        ("request_id", id),
        ("operation_id", id),
        ("body", frame),
        ("request", artifact),
        ("prefix_frontier", json::U64_STRING),
        ("auxiliary_uploads", uploads),
        (
            "maximum_auxiliary_originals",
            json::array(2, json::DECIMAL)?,
        ),
        ("arguments", frame),
        ("unsigned_request", artifact),
        ("original", frame),
        ("context", artifact),
        ("artifact", artifact),
        ("canonical", json::raw_bytes(frame)?),
        ("cut_present", 4),
        ("terminal", frame),
        ("decoded", response_data(frame, "capture")?),
        ("roots", roots),
        ("capture_frontier", json::U64_STRING),
        ("confirmation", confirmation),
        ("stage", json::literal("complete")?),
    ])
}

fn auxiliary_original_data(frame: usize) -> Result<usize, ProviderError> {
    let body = json::object(&[("kind", json::literal("finish")?), ("data", frame)])?;
    // blob_finish has the longest closed auxiliary result discriminator.
    json::object(&[
        ("request_id", json::string(128)?),
        ("body", body),
        (
            "continuation",
            MAXIMUM_RESTORED_SETTLED_CAPTURE_ARTIFACT_BYTES,
        ),
        ("extension", frame),
        ("original", frame),
        ("cut_present", 4),
        ("terminal", frame),
        ("decoded", response_data(frame, "blob_finish")?),
        ("frontier", json::U64_STRING),
        ("stage", json::literal("complete")?),
    ])
}

fn response_data(frame: usize, kind: &str) -> Result<usize, ProviderError> {
    // HistoricalResponseBodyData retains the raw shape and the independently
    // decoded method result. Both serialize the corresponding wire subtrees;
    // the closed kind/data wrapper is additional JSON, not another DTO census.
    let result = json::object(&[("kind", json::literal(kind)?), ("data", frame)])?;
    json::object(&[("shape", frame), ("result", result)])
}

pub(super) fn journals_data(
    frame: usize,
    outgoing: usize,
    incoming: usize,
) -> Result<usize, ProviderError> {
    let canonical = original_json_value_storage_extent_data(frame)?.maximum_canonical_encoded_bytes;
    let original = json::object(&[
        ("request", canonical),
        ("identity", json::hash("cnp.request.v1")?),
        ("response", canonical),
    ])?;
    let entry = json::add(json::add(json::string(128)?, original)?, 2)?;
    // Consumed journal bytes are a numeric usize token. No original is
    // removed or admitted from this row; both namespaces keep their old limits.
    // The enclosing construction separately prices the changed quota scalars.
    json::add(
        json::multiply(json::add(outgoing, incoming)?, entry)?,
        json::DECIMAL,
    )
}

pub(super) fn counter_scratch_data() -> usize {
    std::mem::size_of::<[(&str, usize); 21]>()
        + std::mem::size_of::<[(&str, usize); 11]>()
        + std::mem::size_of::<[(&str, usize); 10]>()
        + std::mem::size_of::<[(&str, usize); 9]>()
        + std::mem::size_of::<std::array::IntoIter<usize, 2>>()
        + std::mem::size_of::<[usize; 8]>()
        + json::counter_scratch_data()
        + crate::client::ClientContent::capture_history_encoding_counter_scratch_data()
        + crate::client::ClientSession::capture_history_encoding_counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_rosters_and_two_independent_journals_are_finite_and_monotone()
    -> Result<(), ProviderError> {
        let a = sdk_history_data(65_536, [3, 3])?;
        let b = sdk_history_data(65_536, [4, 3])?;
        assert!(b > a);
        assert!(sdk_history_data(usize::MAX, [3, 3]).is_err());
        let journals = journals_data(65_536, 8, 9)?;
        assert!(journals > journals_data(65_536, 8, 8)?);
        let canonical =
            original_json_value_storage_extent_data(65_536)?.maximum_canonical_encoded_bytes;
        assert!(journals >= 2 * (8 + 9) * canonical);
        assert!(a > json::raw_bytes(65_536)?);
        Ok(())
    }

    #[test]
    fn actual_raw_and_independently_decoded_reply_and_journal_fit()
    -> Result<(), Box<dyn std::error::Error>> {
        let frame = 65_536;
        let body = BlobChunkRequest {
            transfer_id: Id::new("actual-sdk-journal-transfer")?,
            offset: U64::new(0),
            bytes: Bytes::new(vec![255; 3073]),
            extensions: Extensions::new(),
        };
        let mut original = crate::handshake::tests::original_hello_envelope();
        original.method = Method::BlobChunk;
        original.body = serde_json::from_value(serde_json::to_value(&body)?)?;
        let mut terminal = original.clone();
        terminal.message = MessageKind::Response;
        terminal.body = serde_json::from_value(serde_json::to_value(ResponseShape::Completed {
            operation_state: OperationState::Completed,
            result: serde_json::from_value(serde_json::to_value(BlobChunkResult {
                transfer_id: body.transfer_id.clone(),
                next_offset: U64::new(3073),
            })?)?,
            extensions: Extensions::new(),
        })?)?;
        let decoded =
            crate::bodies::decode_response(&RequestBody::BlobChunk(body), &terminal.body)?;
        let typed = crate::retained_metadata::historical_response_body_data(&decoded)?;
        assert!(serde_json::to_vec(&original)?.len() <= frame);
        assert!(serde_json::to_vec(&terminal)?.len() <= frame);
        assert!(serde_json::to_vec(&typed)?.len() <= response_data(frame, "blob_chunk")?);

        let journal = std::collections::BTreeMap::from([(
            Id::new("actual-original")?,
            crate::client::ClientOriginal {
                request: original,
                identity: crucible_node_format::canonical::hash(
                    "cnp.request.v1",
                    b"ordinary DATA journal",
                )?,
                response: Some(terminal),
            },
        )]);
        assert!(serde_json::to_vec(&journal)?.len() <= journals_data(frame, 1, 0)?);
        Ok(())
    }
}
