//! Synthetic envelope compatibility, extent credit and original byte regressions.

use super::*;

fn large_capture() -> Result<CapturedTranscript, TranscriptError> {
    let origin = origin();
    let input_bytes = vec![0x5a; 65_536];
    let input = object(&input_bytes);
    let body = ControlRequest::Stage {
        input: RecordedInput {
            node: origin.route.node.clone(),
            stage_operation: id("original/large-stage"),
            batch: id("original/large-batch"),
            owners: origin.route.owners.clone(),
            cutoff: position(0),
            inventory: input.reference.clone(),
            deliveries: Vec::new(),
            payloads: vec![input],
            provenance: None,
        },
    };
    let limits = TranscriptLimits {
        maximum_records: 4.into(),
        maximum_record_bytes: 1_000_000.into(),
        maximum_total_bytes: 4_000_000.into(),
    };
    let mut capture = CaptureSession::new_selected(origin, limits, true)?;
    let context = capture.context()?;
    let request = request(
        TranscriptAction::StageInput,
        id("original/large-stage"),
        position(0),
        context,
        &body,
    )?;
    assert!(request.bytes.len() > 65_536);
    assert!(encode(&request).is_err());
    assert!(capture.request_bytes(&request)?.len() > request.bytes.len());

    let evidence = object(&vec![0xa5; 65_537]);
    let reservation = capture.reserve()?;
    capture.retain(
        reservation,
        request,
        encode(&ControlResponse::Acknowledged)?,
        vec![evidence],
        Vec::new(),
        PhysicalTimingUncertainty::Unbounded,
    )?;
    capture.finish()
}

#[test]
fn byte_wire_large_stage_and_evidence_round_trip_original_typed_bodies()
-> Result<(), TranscriptError> {
    let capture = large_capture()?;
    let decoded = BoundaryTranscript::from_canonical_bytes(capture.bytes())?;
    assert_eq!(&decoded, capture.transcript());
    assert_eq!(decoded.canonical_bytes()?, capture.bytes());
    let metadata = decoded.records[0].request.request_metadata()?;
    assert_eq!(metadata.input_batch, Some(id("original/large-batch")));
    assert_eq!(decoded.schema_version, 2);
    for record in &decoded.records {
        record
            .request
            .content
            .verify(&record.request.bytes)
            .map_err(super::super::codec::invalid)?;
        for body in &record.evidence {
            body.reference
                .verify(&body.bytes)
                .map_err(super::super::codec::invalid)?;
        }
    }
    Ok(())
}

#[test]
fn byte_wire_private_signer_reopens_exact_large_source() -> Result<(), TranscriptError> {
    let capture = large_capture()?;
    let expected = capture.bytes().to_vec();
    let limits = capture.transcript().limits.clone();
    let directory = Directory::new();
    let archive = TranscriptArchive::open(&directory.0, limits.clone())?;
    let saved = archive.persist(capture)?;
    let reference = saved.reference().clone();
    drop(saved);
    drop(archive);
    let reopened = TranscriptArchive::open(&directory.0, limits)?.load(&reference)?;
    assert_eq!(reopened.bytes(), expected);
    Ok(())
}

#[test]
fn byte_wire_legacy_envelope_bytes_remain_exact() -> Result<(), TranscriptError> {
    let original = capture();
    assert_eq!(original.transcript().schema_version, 1);
    assert_eq!(encode(original.transcript())?, original.bytes());
    assert_eq!(
        BoundaryTranscript::from_canonical_bytes(original.bytes())?.canonical_bytes()?,
        original.bytes()
    );
    Ok(())
}

#[test]
fn byte_wire_rejects_uppercase_odd_or_non_hex_before_body_decode() -> Result<(), TranscriptError> {
    let original = large_capture()?;
    for malformed in [
        "A5".repeat(65_537),
        "0".repeat(65_537 * 2 + 1),
        "gg".repeat(65_537),
    ] {
        let mut value: serde_json::Value =
            serde_json::from_slice(original.bytes()).map_err(super::super::codec::invalid)?;
        value["records"][0]["evidence"][0]["bytes"] = malformed.into();
        assert!(super::super::byte_wire::decode(value).is_err());
    }
    Ok(())
}

#[test]
fn byte_wire_rejects_changed_full_reference_and_body() -> Result<(), TranscriptError> {
    let original = large_capture()?;
    for changed in [false, true] {
        let mut value: serde_json::Value =
            serde_json::from_slice(original.bytes()).map_err(super::super::codec::invalid)?;
        if changed {
            value["records"][0]["evidence"][0]["reference"]["length"] = "1".into();
        } else {
            value["records"][0]["evidence"][0]["bytes"] = "00".repeat(65_537).into();
        }
        assert!(super::super::byte_wire::decode(value).is_err());
    }
    Ok(())
}

#[test]
fn byte_wire_complete_encoded_record_credit_precedes_retention() -> Result<(), TranscriptError> {
    let original = large_capture()?;
    let record = &original.transcript().records[0];
    let encoded = super::super::byte_wire::record(record, 1_000_000)?;
    assert!(super::super::byte_wire::record(record, encoded.len() as u64 - 1).is_err());
    assert_eq!(
        super::super::byte_wire::record(record, encoded.len() as u64)?,
        encoded
    );
    Ok(())
}

#[test]
fn byte_wire_aggregate_decoded_credit_and_unknown_fields_refuse() -> Result<(), TranscriptError> {
    let original = large_capture()?;
    let mut value: serde_json::Value =
        serde_json::from_slice(original.bytes()).map_err(super::super::codec::invalid)?;
    value["limits"]["maximum_record_bytes"] = "100000".into();
    value["limits"]["maximum_total_bytes"] = "100000".into();
    assert!(super::super::byte_wire::decode(value).is_err());

    let mut value: serde_json::Value =
        serde_json::from_slice(original.bytes()).map_err(super::super::codec::invalid)?;
    value["records"][0]["evidence"][0]["unscoped"] = true.into();
    assert!(super::super::byte_wire::decode(value).is_err());
    Ok(())
}

#[test]
fn byte_wire_inner_control_body_array_ceiling_remains_independent() -> Result<(), TranscriptError> {
    let bytes = vec![0; 65_537];
    assert!(encode(&object(&bytes)).is_err());
    // Envelope selection never changes the original inner control representation.
    let original = large_capture()?;
    let body: ControlRequest =
        serde_json::from_slice(&original.transcript().records[0].request.bytes)
            .map_err(super::super::codec::invalid)?;
    assert_eq!(
        encode(&body)?,
        original.transcript().records[0].request.bytes
    );
    Ok(())
}
