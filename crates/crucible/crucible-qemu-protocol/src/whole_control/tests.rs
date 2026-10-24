//! Complete portable body and constructor-bound conformance controls.

// crucible-lint: allow panic-shortcut -- Conformance fixtures panic on invalid bytes or failed invariants.
#![allow(clippy::unwrap_used)]

use super::body::*;
use super::*;

fn profile() -> WholeControlProfile {
    WholeControlProfile {
        scope: [1; 32],
        operation_capacity: 128,
        body_byte_limit: WHOLE_BODY_MAX_BYTES,
        native_history_byte_limit: 32 * 1024 * 1024,
        provider_history_byte_limit: 32 * 1024 * 1024,
        administrative_read_attempt_limit: 1024,
        administrative_read_byte_limit: 32 * 1024 * 1024,
        administrative_write_attempt_limit: 1024,
        administrative_write_byte_limit: 32 * 1024 * 1024,
        deadline_monotonic_ns: 1_000_000,
        cpu_retirement_limit: 128,
        event_step_limit: 128,
        input_byte_limit: 0,
        input_record_limit: 0,
        output_byte_limit: 0,
        output_record_limit: 0,
    }
}

#[test]
fn actual_native_empty_payload_vectors_round_trip_complete_body_bytes() {
    // These complete public-protocol bodies were emitted by the configured
    // native C codec's zero-payload constructor control, including its hashes.
    let request_body = include_bytes!("testdata/native-zero-request.bin");
    let result_body = include_bytes!("testdata/native-zero-result.bin");
    let ack_body = include_bytes!("testdata/native-zero-ack.bin");
    let request = WholeRequest::decode(request_body).unwrap();
    assert_eq!(request.input_inventory.len(), 8);
    assert_eq!(request.quota.input_bytes, 0);
    assert_eq!(request.quota.input_records, 0);
    let mut encoded_request = [0; 264];
    request.encode_into(&mut encoded_request).unwrap();
    assert_eq!(&encoded_request, request_body);

    let result = WholeResult::decode(result_body).unwrap();
    result.validate_against(request_body).unwrap();
    let mut encoded_result = [0; 344];
    result.encode_into(&mut encoded_result).unwrap();
    assert_eq!(&encoded_result, result_body);
    let acknowledgement = WholeAcknowledgement::decode(ack_body).unwrap();
    acknowledgement
        .validate_against(request_body, result_body)
        .unwrap();
    assert_eq!(&acknowledgement.encode().unwrap(), ack_body);
}

fn request(inventory: &[u8]) -> WholeRequest<'_> {
    WholeRequest {
        scope: [1; 32],
        epoch: 7,
        sequence: 1,
        grant_digest: [2; 32],
        binding_digest: [3; 32],
        start_ps: 0,
        limit_ps: 50,
        quota: WholeOperationQuota {
            input_bytes: 0,
            input_records: 0,
            output_bytes: 0,
            output_records: 0,
            cpu_retirements: 1,
            event_steps: 1,
        },
        input_inventory: inventory,
    }
}

fn result<'a>(request_body: &[u8], inventory: &'a [u8]) -> WholeResult<'a> {
    WholeResult {
        scope: [1; 32],
        epoch: 7,
        sequence: 1,
        request_digest: whole_request_digest(request_body).unwrap(),
        binding_digest: [3; 32],
        input_inventory_digest: domain_digest(
            b"crucible.qemu.whole.input-inventory.v1\0",
            WholeRequest::decode(request_body).unwrap().input_inventory,
        ),
        stopped_ps: 50,
        limit_ps: 50,
        raw_before: 100,
        raw_after: 101,
        retired: 1,
        callbacks: 1,
        input_records: 0,
        input_bytes: 0,
        output_records: 0,
        output_bytes: 0,
        cut: 9,
        disposition: WholeResultDisposition::Complete,
        event_steps: 1,
        event_allowance: 1,
        output_inventory: inventory,
    }
}

#[test]
fn profile_preserves_all_constructor_bounds_in_168_big_endian_bytes() {
    let selected = profile();
    let encoded = selected.encode().unwrap();
    assert_eq!(&encoded[..8], b"CWHLPRO\0");
    assert_eq!(&encoded[48..52], &128_u32.to_be_bytes());
    assert_eq!(&encoded[52..56], &65_536_u32.to_be_bytes());
    assert_eq!(&encoded[136..144], &0_u64.to_be_bytes());
    assert_eq!(WholeControlProfile::decode(&encoded).unwrap(), selected);

    for extent in 0..WHOLE_PROFILE_BYTES {
        assert!(WholeControlProfile::decode(&encoded[..extent]).is_err());
    }
    for offset in [0, 8, 12, 160, 167] {
        let mut changed = encoded;
        changed[offset] ^= 1;
        assert!(WholeControlProfile::decode(&changed).is_err());
    }
    let mut changed = selected;
    changed.input_record_limit = 1;
    assert_ne!(changed.digest().unwrap(), profile().digest().unwrap());
}

#[test]
fn profile_rejects_inadequate_complete_history_before_encoding() {
    let mut selected = profile();
    selected.native_history_byte_limit = 128 * 2 * 65_536;
    assert_eq!(selected.encode(), Err(WholeControlError::Budget));
    selected = profile();
    selected.operation_capacity = 0;
    assert_eq!(selected.encode(), Err(WholeControlError::Budget));
    selected = profile();
    selected.operation_capacity = WHOLE_OPERATION_MAX + 1;
    assert_eq!(selected.encode(), Err(WholeControlError::Budget));
}

#[test]
fn complete_body_commitments_include_variable_inventory_and_consumed_ack() {
    let request_inventory = [0; 16];
    let mut request_body = vec![0; WHOLE_REQUEST_HEADER_BYTES + request_inventory.len()];
    request(&request_inventory)
        .encode_into(&mut request_body)
        .unwrap();
    assert_eq!(&request_body[..8], &[0, 0, 0, 1, 0, 0, 1, 16]);
    let output = [0; 16];
    let original_result = result(&request_body, &output);
    let mut result_body = vec![0; WHOLE_RESULT_HEADER_BYTES + output.len()];
    original_result.encode_into(&mut result_body).unwrap();
    WholeResult::decode(&result_body)
        .unwrap()
        .validate_against(&request_body)
        .unwrap();
    let ack = WholeAcknowledgement::for_complete(&request_body, &result_body).unwrap();
    let consumed = WholeAcknowledgement::decode(&ack.encode().unwrap()).unwrap();
    consumed
        .validate_against(&request_body, &result_body)
        .unwrap();

    request_body[WHOLE_REQUEST_HEADER_BYTES] = 1;
    assert_eq!(
        WholeRequest::decode(&request_body),
        Err(WholeControlError::Correlation)
    );
    request_body[WHOLE_REQUEST_HEADER_BYTES] = 0;
    result_body[WHOLE_RESULT_HEADER_BYTES] = 1;
    assert_eq!(
        WholeResult::decode(&result_body),
        Err(WholeControlError::Correlation)
    );
}

#[test]
fn unknown_result_keeps_complete_bytes_but_cannot_be_acknowledged() {
    let input = [0; 16];
    let mut request_body = vec![0; WHOLE_REQUEST_HEADER_BYTES + input.len()];
    request(&input).encode_into(&mut request_body).unwrap();
    let output = [4; 16];
    let mut uncertain = result(&request_body, &output);
    uncertain.disposition = WholeResultDisposition::Unknown;
    uncertain.stopped_ps = 0;
    let mut result_body = vec![0; WHOLE_RESULT_HEADER_BYTES + output.len()];
    uncertain.encode_into(&mut result_body).unwrap();
    assert_eq!(
        WholeResult::decode(&result_body).unwrap().output_inventory,
        output
    );
    assert_eq!(
        WholeAcknowledgement::for_complete(&request_body, &result_body),
        Err(WholeControlError::Unknown)
    );
}

#[test]
fn envelope_refuses_foreign_editions_and_caps_before_body_collection() {
    let header = encode_whole_frame_header(WholeFrameKind::Request, 272, 512).unwrap();
    assert_eq!(
        decode_whole_frame_header(&header, 512).unwrap(),
        (WholeFrameKind::Request, 272)
    );
    assert!(decode_whole_frame_header(&header, 256).is_err());
    for extent in 0..WHOLE_FRAME_HEADER_BYTES {
        assert!(decode_whole_frame_header(&header[..extent], 512).is_err());
    }
    let mut foreign = header;
    foreign[11] = 2;
    assert!(decode_whole_frame_header(&foreign, 512).is_err());
    foreign = header;
    foreign[23] = 1;
    assert!(decode_whole_frame_header(&foreign, 512).is_err());
}
