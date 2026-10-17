//! Borrowed/owned wire parity and explicit malformed-input precedence.

use super::*;

fn response(status: BlockStatus, data: Vec<u8>) -> Vec<u8> {
    BlockResponse {
        status,
        epoch: 7,
        request_id: 13,
        data,
    }
    .encode()
    .unwrap()
}

fn same_error(bytes: &[u8], expected: BlockCodecError) {
    assert_eq!(BlockResponse::decode(bytes).unwrap_err(), expected);
    match BlockResponse::decode_borrowed(bytes) {
        Err(error) => assert_eq!(error, expected),
        Ok(_) => panic!("malformed input must refuse before returning a view"),
    }
}

#[test]
fn every_status_shares_grammar_and_borrows_the_actual_input() {
    let mut reset = vec![0; 32];
    reset[19] = BlockErrorCode::NoSpace.to_wire();
    for status in [
        BlockStatus::Ok,
        BlockStatus::Error,
        BlockStatus::TransportReset,
        BlockStatus::DuplicateIgnored,
        BlockStatus::DuplicateProtocolError,
        BlockStatus::RetryPreserveId,
        BlockStatus::RetryNewId,
        BlockStatus::DropCompletion,
    ] {
        let data = match status {
            BlockStatus::Error | BlockStatus::DuplicateProtocolError => {
                vec![BlockErrorCode::NoSpace.to_wire()]
            }
            BlockStatus::TransportReset => reset.clone(),
            _ => vec![17, 23],
        };
        let mut bytes = response(status, data);
        bytes.extend_from_slice(b"ignored trailing transport bytes");
        let borrowed = BlockResponse::decode_borrowed(&bytes).unwrap();
        let owned = BlockResponse::decode(&bytes).unwrap();

        assert_eq!(borrowed.identity(), owned.identity());
        assert_eq!(borrowed.status, owned.status);
        assert_eq!(borrowed.data, owned.data);
        assert_eq!(
            borrowed.data.as_ptr(),
            bytes[RESPONSE_HEADER_LEN..].as_ptr()
        );
        assert_ne!(owned.data.as_ptr(), borrowed.data.as_ptr());
        assert_eq!(
            validate_response_payload(borrowed.status, borrowed.data),
            Ok(())
        );
    }
}

#[test]
fn every_typed_error_byte_has_identical_owned_and_borrowed_outcome() {
    for code in 0..=255 {
        for status in [BlockStatus::Error, BlockStatus::DuplicateProtocolError] {
            let bytes = response(status, vec![code]);
            match BlockErrorCode::from_wire(code) {
                Ok(expected) => {
                    let borrowed = BlockResponse::decode_borrowed(&bytes).unwrap();
                    let owned = BlockResponse::decode(&bytes).unwrap();
                    assert_eq!(
                        decode_error_code(borrowed.status, borrowed.data),
                        Ok(expected)
                    );
                    assert_eq!(owned.error_code(), Ok(expected));
                }
                Err(error) => same_error(&bytes, error),
            }
        }
    }
}

#[test]
fn header_and_payload_errors_keep_their_exact_order() {
    same_error(
        &[255; RESPONSE_HEADER_LEN - 1],
        BlockCodecError::ShortHeader {
            needed: RESPONSE_HEADER_LEN,
            got: RESPONSE_HEADER_LEN - 1,
        },
    );
    let mut bytes = response(BlockStatus::Error, vec![0]);
    bytes[0] = 255;
    bytes[1] = 255;
    bytes[2] = 1;
    bytes[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    same_error(&bytes, BlockCodecError::UnknownStatus { status: 255 });

    bytes[0] = BlockStatus::Error.to_wire();
    same_error(
        &bytes,
        BlockCodecError::VersionMismatch {
            expected: BLOCK_ABI_VERSION,
            found: 255,
        },
    );
    bytes[1] = BLOCK_ABI_VERSION;
    same_error(&bytes, BlockCodecError::NonZeroReserved { reserved: 1 });
    bytes[2] = 0;
    same_error(
        &bytes,
        BlockCodecError::CountExceedsPayload {
            count: u32::MAX,
            available: 1,
        },
    );
    bytes[16..20].copy_from_slice(&1_u32.to_le_bytes());
    same_error(&bytes, BlockCodecError::UnknownErrorCode { code: 0 });

    for status in [BlockStatus::Error, BlockStatus::DuplicateProtocolError] {
        for data in [Vec::new(), vec![1, 2]] {
            same_error(
                &response(status, data.clone()),
                BlockCodecError::InvalidErrorPayload {
                    status: status.to_wire(),
                    len: data.len(),
                },
            );
        }
    }
}

#[test]
fn reset_payload_validation_preserves_reserved_and_discriminator_priority() {
    same_error(
        &response(BlockStatus::TransportReset, vec![0; 31]),
        BlockCodecError::InvalidResetPayload { len: 31 },
    );
    let mut data = vec![0; 32];
    data[27] = 1;
    same_error(
        &response(BlockStatus::TransportReset, data.clone()),
        BlockCodecError::InvalidResetPayload { len: 32 },
    );
    data[27] = 0;
    same_error(
        &response(BlockStatus::TransportReset, data.clone()),
        BlockCodecError::UnknownErrorCode { code: 0 },
    );
    data[19] = BlockErrorCode::NoSpace.to_wire();
    for offset in [16, 17, 18, 20, 21, 22, 23, 24, 25, 26] {
        let mut invalid = data.clone();
        invalid[offset] = 255;
        same_error(
            &response(BlockStatus::TransportReset, invalid),
            BlockCodecError::InvalidResetPayload { len: 32 },
        );
    }
}
