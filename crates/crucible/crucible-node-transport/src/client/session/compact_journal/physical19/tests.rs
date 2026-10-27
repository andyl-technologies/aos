//! Checks independent lifetime ceilings, content ownership and edition refusal.

use super::*;
use crate::bodies::{BlobBeginRequest, BlobChunkRequest, BlobFinishRequest};
use crate::client::{ClientContent, ClientCustody};
use crate::connection::{ReceivedBody, ReceivedFrame};
use crate::envelope::{MessageKind, RequestOrigin};
use crate::retained_metadata::records::ValidatedMetadataRecords;
use crucible_node_format::{Bytes, Extensions, Id, U64};
use serde_json::{Value, json};

use super::super::physical18::tests::limits;
use super::super::tests::{BANK_BYTES, TestResult, fixture};

fn capture(custody: &CompactClientCustody) -> Result<Vec<u8>, ProviderError> {
    let mut records = MetadataRecordBank::reserve(4096)?;
    serde_json::to_vec(&custody.physical_custody19_data(&mut records)?)
        .map_err(crucible_node_format::ContractError::from)
        .map_err(ProviderError::from)
}

fn roundtrip(custody: &CompactClientCustody) -> Result<HistoricalCompactCustody19, ProviderError> {
    let encoded = capture(custody)?;
    let history = HistoricalCompactCustody19::decode(&encoded, limits(&encoded))?;
    let mut records = MetadataRecordBank::reserve(4096)?;
    let repeated = serde_json::to_vec(&history.physical_data(&mut records)?)
        .map_err(crucible_node_format::ContractError::from)?;
    assert_eq!(repeated, encoded);
    assert_eq!(
        history.retained_metadata_facts()?,
        custody.retained_metadata_facts()?
    );
    Ok(history)
}

#[test]
fn actual_initial_capacity_growth_keeps_distinct_ceilings_and_reserved_content() -> TestResult {
    let bytes = b"same original content";
    let reference =
        crucible_node_format::canonical::content_ref(bytes, "application/octet-stream")?;
    let mut content = ClientContent::new(262_144, 8, 4096)?;
    content.install(reference.clone(), bytes.to_vec())?;
    let mut initial = ClientCustody::new(8, content)?;
    initial.prepare_original_host_initial_capacity_data(4096)?;
    let journal_ceiling = initial.maximum_bytes;
    let mut content = initial.content;
    let content_ceiling = content.byte_ceiling();
    assert_eq!(journal_ceiling, 266_240);
    assert_eq!(content_ceiling, 393_216);

    // Completed and unfinished transfers retain their original reservations,
    // including a second reservation for a digest already installed locally.
    let transfer_id = Id::new("completed-content-view")?;
    content.begin(&BlobBeginRequest {
        transfer_id: transfer_id.clone(),
        content: reference.clone(),
        extensions: Extensions::new(),
    })?;
    content.chunk(&BlobChunkRequest {
        transfer_id: transfer_id.clone(),
        offset: U64::new(0),
        bytes: Bytes::new(bytes.to_vec()),
        extensions: Extensions::new(),
    })?;
    content.finish(&BlobFinishRequest {
        transfer_id,
        extensions: Extensions::new(),
    })?;
    content.begin(&BlobBeginRequest {
        transfer_id: Id::new("reserved-incomplete")?,
        content: crucible_node_format::canonical::content_ref(
            b"unfinished",
            "application/octet-stream",
        )?,
        extensions: Extensions::new(),
    })?;
    let before = serde_json::to_vec(&content.original_compact_metadata8_view())?;

    let custody =
        CompactClientCustody::with_journal_byte_ceiling(8, journal_ceiling, content, BANK_BYTES)?;
    let history = roundtrip(&custody)?;

    assert_eq!(
        history.journal_limits_data(),
        [8, journal_ceiling, 0, BANK_BYTES]
    );
    assert_eq!(history.content_data().byte_ceiling(), content_ceiling);
    assert_eq!(history.content_data().get(&reference)?, bytes);
    assert_eq!(
        serde_json::to_vec(&history.content_data().original_compact_metadata8_view())?,
        before
    );
    Ok(())
}

#[test]
fn both_ceiling_orders_preserve_originals_and_consumed_journal_credit() -> TestResult {
    let (_lease, _session, _coupled, _peer, mut request) = fixture(BANK_BYTES);
    for (journal_bytes, content_bytes) in [(4096, 65_536), (65_536, 4096)] {
        let mut custody = CompactClientCustody::with_journal_byte_ceiling(
            8,
            journal_bytes,
            ClientContent::new(content_bytes, 8, 4096)?,
            9 * journal_bytes,
        )?;
        let id = Id::new("independent-original")?;
        request.request_id.0 = Some(id.clone());
        for origin in [RequestOrigin::Controller, RequestOrigin::Provider] {
            custody
                .journal
                .retain_request(origin, &request, 0, 65_536)?;
            let mut response = request.clone();
            response.message = MessageKind::Response;
            custody.journal.hold(origin, response)?;
            custody.journal.complete_response(&id)?;
        }
        let consumed = custody.retained_journal_bytes();
        assert!(consumed > 0);

        let history = roundtrip(&custody)?;

        assert_eq!(
            history.journal_limits_data(),
            [8, journal_bytes, consumed, 9 * journal_bytes]
        );
        assert_eq!(history.content_data().byte_ceiling(), content_bytes);
        for origin in [RequestOrigin::Controller, RequestOrigin::Provider] {
            let original = history.original_data(origin, &id).unwrap();
            assert_eq!(original.materialize_request()?, request);
            assert!(original.has_response());
        }
    }
    Ok(())
}

#[test]
fn neither_unused_budget_can_fund_the_other_population() -> TestResult {
    let (_lease, _session, _coupled, _peer, mut request) = fixture(BANK_BYTES);
    let mut custody = CompactClientCustody::with_journal_byte_ceiling(
        8,
        1024,
        ClientContent::new(65_536, 8, 4096)?,
        9 * 1024,
    )?;
    request
        .body
        .insert("payload".into(), json!("x".repeat(2048)));
    assert!(
        custody
            .journal
            .retain_request(RequestOrigin::Controller, &request, 0, 65_536)
            .is_err()
    );
    assert_eq!(custody.retained_journal_bytes(), 0);
    assert_eq!(custody.content.byte_ceiling(), 65_536);

    let mut custody = CompactClientCustody::with_journal_byte_ceiling(
        8,
        65_536,
        ClientContent::new(4, 8, 4096)?,
        BANK_BYTES / 4,
    )?;
    let bytes = b"longer than content credit";
    let reference =
        crucible_node_format::canonical::content_ref(bytes, "application/octet-stream")?;
    assert!(custody.content.install(reference, bytes.to_vec()).is_err());
    assert_eq!(custody.journal.maximum_bytes, 65_536);
    assert_eq!(custody.retained_journal_bytes(), 0);
    Ok(())
}

#[test]
fn slot_construction_preserves_original_content_and_occupied_output_on_refusal() -> TestResult {
    let bytes = b"already retained original";
    let reference =
        crucible_node_format::canonical::content_ref(bytes, "application/octet-stream")?;
    let mut content = ClientContent::new(65_536, 8, 4096)?;
    content.install(reference.clone(), bytes.to_vec())?;
    let mut input = Some(content);
    let mut output = None;
    let original_pointer = input.as_ref().unwrap().get(&reference)?.as_ptr();
    let before = serde_json::to_vec(&input.as_ref().unwrap().original_compact_metadata8_view())?;

    for (requests, journal, bank) in [
        (0, 4096, 1),
        (4097, 4096, 1),
        (8, 0, 1),
        (8, 4096, 0),
        (8, 4096, 9 * 4096 + 1),
        (8, usize::MAX, 1),
    ] {
        assert!(
            CompactClientCustody::retain_with_journal_byte_ceiling_into(
                requests,
                journal,
                &mut input,
                bank,
                &mut output
            )
            .is_err()
        );
        assert!(output.is_none());
        assert_eq!(
            input.as_ref().unwrap().get(&reference)?.as_ptr(),
            original_pointer
        );
        assert_eq!(
            serde_json::to_vec(&input.as_ref().unwrap().original_compact_metadata8_view())?,
            before
        );
    }

    CompactClientCustody::retain_with_journal_byte_ceiling_into(
        8,
        4096,
        &mut input,
        9 * 4096,
        &mut output,
    )?;
    assert!(input.is_none());
    let custody = output.as_ref().unwrap();
    assert_eq!(
        custody.content().get(&reference)?.as_ptr(),
        original_pointer
    );
    assert_eq!(
        serde_json::to_vec(&custody.content().original_compact_metadata8_view())?,
        before
    );
    let captured = capture(custody)?;
    input = Some(ClientContent::new(1024, 8, 4096)?);

    assert!(
        CompactClientCustody::retain_with_journal_byte_ceiling_into(
            8,
            1024,
            &mut input,
            9 * 1024,
            &mut output
        )
        .is_err()
    );
    assert!(input.is_some());
    assert_eq!(capture(output.as_ref().unwrap())?, captured);
    let mut absent = None;
    let mut empty_output = None;
    assert!(
        CompactClientCustody::retain_with_journal_byte_ceiling_into(
            8,
            1024,
            &mut absent,
            9 * 1024,
            &mut empty_output
        )
        .is_err()
    );
    assert!(empty_output.is_none());
    Ok(())
}

#[test]
fn actual_socket_exchange_keeps_independent_ceilings_and_nonrenewing_history() -> TestResult {
    let (_lease, mut session, _coupled, mut peer, mut request) = fixture(BANK_BYTES);
    let mut custody = CompactClientCustody::with_journal_byte_ceiling(
        8,
        262_144,
        ClientContent::new(4096, 8, 4096)?,
        BANK_BYTES,
    )?;
    let server = std::thread::spawn(move || {
        let mut reader =
            crate::transport::FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
        let value = reader.read().unwrap().unwrap();
        let mut response: crate::envelope::Envelope = serde_json::from_value(value).unwrap();
        response.message = MessageKind::Response;
        response.body = json!({
            "status": "error", "operation_state": "not_started",
            "error": {
                "code": "RESOURCE_EXHAUSTED", "message": "bounded refusal",
                "effect": "not_started", "retryable": true, "details": {"original": true}
            },
            "extensions": {}
        })
        .as_object()
        .unwrap()
        .clone();
        let value = serde_json::to_value(&response).unwrap();
        crate::transport::write_frame(&mut peer, &value, 65_536).unwrap();
        response
    });

    let response = session.exchange_compact(
        &mut custody,
        &mut request,
        std::time::Duration::from_secs(5),
    )?;
    assert_eq!(response, server.join().unwrap());
    let charged = custody.retained_journal_bytes();
    assert!(charged > 0);
    let history = roundtrip(&custody)?;

    assert_eq!(
        history.journal_limits_data(),
        [8, 262_144, charged, BANK_BYTES]
    );
    assert_eq!(history.content_data().byte_ceiling(), 4096);
    assert!(
        history
            .original_data(
                RequestOrigin::Controller,
                request.request_id.0.as_ref().unwrap()
            )
            .unwrap()
            .has_response()
    );
    Ok(())
}

#[test]
fn editions_refuse_each_other_and_old_writer_refuses_unequal_ceilings_before_census() -> TestResult
{
    let (_lease, _session, coupled, _peer, _request) = fixture(BANK_BYTES);
    let mut records = MetadataRecordBank::reserve(4096)?;
    let old = serde_json::to_vec(&coupled.physical_custody18_data(&mut records)?)?;
    assert!(HistoricalCompactCustody19::decode(&old, limits(&old)).is_err());
    HistoricalCompactCustody18::decode(&old, limits(&old))?;

    let new = capture(&coupled)?;
    assert!(HistoricalCompactCustody18::decode(&new, limits(&new)).is_err());
    let old_text = std::str::from_utf8(&old)?;
    assert_eq!(
        std::str::from_utf8(&new)?,
        old_text.replacen("compact-custody/18", "compact-custody/19", 1)
    );

    let custody = CompactClientCustody::with_journal_byte_ceiling(
        8,
        4096,
        ClientContent::new(65_536, 8, 4096)?,
        9 * 4096,
    )?;
    let mut records = MetadataRecordBank::reserve(4096)?;
    assert!(custody.physical_custody18_data(&mut records).is_err());
    assert!(records.rows().is_empty());
    let new = capture(&custody)?;
    let retagged =
        std::str::from_utf8(&new)?.replacen("compact-custody/19", "compact-custody/18", 1);
    assert!(
        HistoricalCompactCustody18::decode(retagged.as_bytes(), limits(retagged.as_bytes()))
            .is_err()
    );
    roundtrip(&custody)?;
    Ok(())
}

#[test]
fn failed_received_owners_keep_independent_details_and_capacity() -> TestResult {
    let (_lease, _session, _coupled, _peer, mut request) = fixture(BANK_BYTES);
    let mut custody = CompactClientCustody::with_journal_byte_ceiling(
        8,
        4096,
        ClientContent::new(65_536, 8, 4096)?,
        9 * 4096,
    )?;
    request.protocol.reserve(1024);
    custody
        .journal
        .hold(RequestOrigin::Controller, request.clone())?;
    custody.journal.unexpected = Some(ReceivedFrame {
        envelope: request,
        body: ReceivedBody::Notification(Box::new(crate::bodies::NotificationBody {
            operation_state: crate::bodies::OperationState::Unknown,
            last_observation_sequence: U64::new(u64::MAX),
            details: json!({"independent": [false, -0.0, "typed"]})
                .as_object()
                .unwrap()
                .clone(),
            extensions: Extensions::new(),
        })),
    });

    let history = roundtrip(&custody)?;

    assert_eq!(history.pending_envelope_data(), custody.pending_envelope());
    let ReceivedBody::Notification(body) = &history.unexpected_frame_data().unwrap().body else {
        panic!("lost independently typed failure body");
    };
    assert_eq!(body.details["independent"], json!([false, -0.0, "typed"]));
    assert_eq!(history.journal_limits_data()[2], 0);
    Ok(())
}

#[test]
fn independent_history_refuses_truncation_and_one_short_capacity_restrictions() -> TestResult {
    let mut custody = CompactClientCustody::with_journal_byte_ceiling(
        8,
        4096,
        ClientContent::new(65_536, 8, 4096)?,
        9 * 4096,
    )?;
    let bytes = b"original capacity";
    let reference =
        crucible_node_format::canonical::content_ref(bytes, "application/octet-stream")?;
    custody.content.install(reference, bytes.to_vec())?;
    let encoded = capture(&custody)?;
    let bound = limits(&encoded);
    for end in 0..encoded.len() {
        assert!(
            HistoricalCompactCustody19::decode(&encoded[..end], bound).is_err(),
            "accepted prefix {end}"
        );
    }
    let value: Value = serde_json::from_slice(&encoded)?;
    let rows = serde_json::to_vec(&value[3])?;
    let rows = ValidatedMetadataRecords::validate(&rows, 4096, usize::MAX)?;
    let mut exact = bound;
    exact.maximum_capacity_rows = rows.row_count();
    exact.maximum_backing_capacity_bytes = rows.backing_capacity_bytes();
    HistoricalCompactCustody19::decode(&encoded, exact)?;
    for short in [
        CompactCustody19Limits {
            maximum_input_bytes: encoded.len() - 1,
            ..exact
        },
        CompactCustody19Limits {
            maximum_capacity_rows: exact.maximum_capacity_rows - 1,
            ..exact
        },
        CompactCustody19Limits {
            maximum_backing_capacity_bytes: exact.maximum_backing_capacity_bytes - 1,
            ..exact
        },
    ] {
        assert!(HistoricalCompactCustody19::decode(&encoded, short).is_err());
    }
    Ok(())
}
