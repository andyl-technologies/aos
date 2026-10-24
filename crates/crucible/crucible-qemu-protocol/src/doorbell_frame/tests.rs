//! Checks borrowed frame storage and the shared decoder's refusal precedence.

use super::*;

#[test]
fn borrowed_frame_retains_literal_payload_and_owned_decode_values() {
    let frame = [
        0x43, 0x52, 0x42, 0x4c, 3, 0, 5, 0, 4, 0, 0, 0, 0x10, 0x20, 0x30, 0x40,
    ];
    let borrowed = WhiteboxDoorbellFrameView::decode_bounded(&frame, 4).unwrap();
    let owned = WhiteboxDoorbellFrame::decode_bounded(&frame, 4).unwrap();

    assert_eq!(borrowed.kind(), 5);
    assert_eq!(borrowed.payload(), &[0x10, 0x20, 0x30, 0x40]);
    assert_eq!(borrowed.payload().as_ptr(), frame[12..].as_ptr());
    assert_eq!(owned.kind(), borrowed.kind());
    assert_eq!(owned.payload(), borrowed.payload());
    assert_ne!(owned.payload().as_ptr(), borrowed.payload().as_ptr());
    assert_eq!(owned.encode().unwrap(), frame);
    assert_eq!(WhiteboxDoorbellFrameView::decode(&frame).unwrap(), borrowed);

    let empty = &frame[..12];
    let mut empty = empty.to_vec();
    empty[8..12].copy_from_slice(&0_u32.to_le_bytes());
    let borrowed = WhiteboxDoorbellFrameView::decode_bounded(&empty, 0).unwrap();
    assert_eq!(borrowed.kind(), 5);
    assert!(borrowed.payload().is_empty());
    assert_eq!(borrowed.payload().as_ptr(), empty[12..].as_ptr());
}

#[test]
fn borrowed_frame_refusals_preserve_header_bound_and_length_precedence() {
    let valid = [
        0x43, 0x52, 0x42, 0x4c, 3, 0, 5, 0, 4, 0, 0, 0, 0x10, 0x20, 0x30, 0x40,
    ];
    let assert_refusal =
        |bytes: &[u8], bound: usize, expected: WhiteboxDoorbellFrameDecodeError| {
            assert_eq!(
                WhiteboxDoorbellFrameView::decode_bounded(bytes, bound),
                Err(expected.clone())
            );
            assert_eq!(
                WhiteboxDoorbellFrame::decode_bounded(bytes, bound),
                Err(expected)
            );
        };

    for length in 0..valid.len() {
        let expected = if length < 12 {
            WhiteboxDoorbellFrameDecodeError::TruncatedFrame {
                len: length,
                minimum_len: 12,
            }
        } else {
            WhiteboxDoorbellFrameDecodeError::PayloadLengthMismatch {
                declared_len: 4,
                actual_len: length - 12,
            }
        };
        assert_refusal(&valid[..length], 4, expected);
    }

    let mut malformed = valid;
    malformed[0] = 0;
    malformed[4] = 0;
    malformed[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_refusal(
        &malformed,
        4,
        WhiteboxDoorbellFrameDecodeError::BadMagic {
            expected: WHITEBOX_DOORBELL_FRAME_MAGIC,
            actual: 0x4c42_5200,
        },
    );

    malformed[0] = valid[0];
    assert_refusal(
        &malformed,
        4,
        WhiteboxDoorbellFrameDecodeError::UnsupportedVersion {
            expected: WHITEBOX_DOORBELL_PROTOCOL_VERSION,
            actual: 0,
        },
    );

    malformed[4] = valid[4];
    assert_refusal(
        &malformed,
        4,
        WhiteboxDoorbellFrameDecodeError::PayloadLengthExceedsBound {
            declared_len: u32::MAX as usize,
            max_payload_len: 4,
        },
    );
    assert_refusal(
        &valid,
        3,
        WhiteboxDoorbellFrameDecodeError::PayloadLengthExceedsBound {
            declared_len: 4,
            max_payload_len: 3,
        },
    );
    malformed[8..12].copy_from_slice(&3_u32.to_le_bytes());
    assert_refusal(
        &malformed,
        4,
        WhiteboxDoorbellFrameDecodeError::PayloadLengthMismatch {
            declared_len: 3,
            actual_len: 4,
        },
    );
}
