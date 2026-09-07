//! Conformance and defensive decoding tests for the selectable ABI.

use super::*;

fn register() -> Result<SelectableRegister, SelectableProtocolError> {
    SelectableRegister::new(
        0x0102_0304_0506_0708,
        "net",
        vec![0xaa, 0xbb],
        vec![1],
        vec![String::from("a"), String::from("z")],
    )
}

fn request() -> Result<SelectionRequest, SelectableProtocolError> {
    SelectionRequest::new(9, "net", "epoch/1", Some(vec![0xaa]), 104)
}

fn selected_reply() -> Result<SelectionReply, SelectableProtocolError> {
    SelectionReply::selected(
        9,
        [1; SELECTABLE_DIGEST_BYTES],
        [2; SELECTABLE_DIGEST_BYTES],
        vec![3, 4],
    )
}

#[test]
fn selectable_registration_v1_has_frozen_canonical_bytes() -> Result<(), SelectableProtocolError> {
    let register = register()?;
    let bytes = register.encode()?;
    let expected = [
        1, 0, 1, 0, 56, 0, 0, 0, 68, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1, 56, 0, 0, 0, 3, 0, 0, 0, 59,
        0, 0, 0, 2, 0, 0, 0, 61, 0, 0, 0, 1, 0, 0, 0, 62, 0, 0, 0, 6, 0, 0, 0, 2, 0, 0, 0, b'n',
        b'e', b't', 0xaa, 0xbb, 1, 1, 0, b'a', 1, 0, b'z',
    ];
    assert_eq!(bytes, expected);
    assert_eq!(SelectableRegister::decode(&bytes), Ok(register));
    Ok(())
}

#[test]
fn selection_request_v1_reserves_one_exact_zeroed_reply_buffer()
-> Result<(), SelectableProtocolError> {
    let request = request()?;
    let bytes = request.encode()?;
    assert_eq!(bytes.len(), 104);
    assert_eq!(
        &bytes[..59],
        &[
            1, 0, 2, 0, 48, 0, 1, 0, 104, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 48, 0, 0, 0, 3, 0, 0, 0,
            51, 0, 0, 0, 7, 0, 0, 0, 58, 0, 0, 0, 1, 0, 0, 0, 59, 0, 0, 0, b'n', b'e', b't', b'e',
            b'p', b'o', b'c', b'h', b'/', b'1', 0xaa,
        ]
    );
    assert!(bytes[59..].iter().all(|byte| *byte == 0));
    assert_eq!(SelectionRequest::decode(&bytes), Ok(request));

    let mut contaminated = bytes;
    contaminated[103] = 1;
    assert_eq!(
        SelectionRequest::decode(&contaminated),
        Err(SelectableProtocolError::NonzeroReplyReservation)
    );
    Ok(())
}

#[test]
fn selection_reply_v1_binds_sequence_ids_status_and_value() -> Result<(), SelectableProtocolError> {
    let selected_reply = selected_reply()?;
    let bytes = selected_reply.encode()?;
    assert_eq!(bytes.len(), 98);
    assert_eq!(
        &bytes[..20],
        &[1, 0, 3, 0, 96, 0, 0, 0, 98, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(&bytes[24..56], &[1; SELECTABLE_DIGEST_BYTES]);
    assert_eq!(&bytes[56..88], &[2; SELECTABLE_DIGEST_BYTES]);
    assert_eq!(&bytes[88..], &[96, 0, 0, 0, 2, 0, 0, 0, 3, 4]);
    assert_eq!(SelectionReply::decode(&bytes), Ok(selected_reply));

    let rejected = SelectionReply::rejected(
        9,
        SelectionReplyStatus::UnknownSelectable,
        [0; SELECTABLE_DIGEST_BYTES],
        [0; SELECTABLE_DIGEST_BYTES],
    )?;
    let rejected_bytes = rejected.encode()?;
    assert_eq!(rejected_bytes.len(), SELECTION_REPLY_HEADER_BYTES);
    assert_eq!(SelectionReply::decode(&rejected_bytes), Ok(rejected));
    Ok(())
}

#[test]
fn selectable_decoders_reject_every_truncation_without_panicking()
-> Result<(), SelectableProtocolError> {
    let register = register()?.encode()?;
    for len in 0..register.len() {
        assert!(SelectableRegister::decode(&register[..len]).is_err());
    }
    let request = request()?.encode()?;
    for len in 0..request.len() {
        assert!(SelectionRequest::decode(&request[..len]).is_err());
    }
    let reply = selected_reply()?.encode()?;
    for len in 0..reply.len() {
        assert!(SelectionReply::decode(&reply[..len]).is_err());
    }
    Ok(())
}

#[test]
fn selectable_decoders_reject_noncanonical_headers_ranges_and_reserved_bits()
-> Result<(), SelectableProtocolError> {
    let registration = register()?.encode()?;
    assert_eq!(
        decode_selectable_message_kind(&registration),
        Ok(SelectableMessageKind::Register)
    );
    assert!(matches!(
        SelectionRequest::decode(&registration),
        Err(SelectableProtocolError::UnexpectedMessageKind {
            expected: SelectableMessageKind::Request,
            actual: SELECTABLE_MESSAGE_KIND_REGISTER,
        })
    ));

    let mut wrong_version = register()?.encode()?;
    wrong_version[0] = 2;
    assert!(matches!(
        SelectableRegister::decode(&wrong_version),
        Err(SelectableProtocolError::UnsupportedVersion { .. })
    ));

    let mut wrong_header = register()?.encode()?;
    wrong_header[4] = 55;
    assert!(matches!(
        SelectableRegister::decode(&wrong_header),
        Err(SelectableProtocolError::HeaderLengthMismatch { .. })
    ));

    let mut gap = register()?.encode()?;
    gap[20] = 57;
    assert_eq!(
        SelectableRegister::decode(&gap),
        Err(SelectableProtocolError::NonCanonicalRangeLayout)
    );

    let mut reserved = register()?.encode()?;
    reserved[54] = 1;
    assert!(matches!(
        SelectableRegister::decode(&reserved),
        Err(SelectableProtocolError::NonzeroReserved {
            field: "reserved",
            ..
        })
    ));

    let mut unknown_flags = request()?.encode()?;
    unknown_flags[6] = 2;
    assert_eq!(
        SelectionRequest::decode(&unknown_flags),
        Err(SelectableProtocolError::UnknownFlags { flags: 2 })
    );

    let mut unknown_status = selected_reply()?.encode()?;
    unknown_status[20] = 99;
    assert_eq!(
        SelectionReply::decode(&unknown_status),
        Err(SelectableProtocolError::UnknownReplyStatus { status: 99 })
    );

    let mut unknown_kind = registration;
    unknown_kind[2] = 99;
    assert_eq!(
        decode_selectable_message_kind(&unknown_kind),
        Err(SelectableProtocolError::UnknownMessageKind { actual: 99 })
    );
    Ok(())
}

#[test]
fn selectable_identifier_tag_and_value_shapes_fail_closed() -> Result<(), SelectableProtocolError> {
    assert!(matches!(
        SelectableRegister::new(0, "bad name", vec![1], vec![1], Vec::new()),
        Err(SelectableProtocolError::InvalidIdentifier { .. })
    ));
    assert_eq!(
        SelectableRegister::new(
            0,
            "valid",
            vec![1],
            vec![1],
            vec![String::from("z"), String::from("a")],
        ),
        Err(SelectableProtocolError::NonCanonicalSemanticTagOrder)
    );
    assert_eq!(
        SelectionReply::rejected(
            1,
            SelectionReplyStatus::Selected,
            [0; SELECTABLE_DIGEST_BYTES],
            [0; SELECTABLE_DIGEST_BYTES],
        ),
        Err(SelectableProtocolError::SelectedValueMissing)
    );

    let mut rejected_with_value = SelectionReply::rejected(
        1,
        SelectionReplyStatus::Unavailable,
        [0; SELECTABLE_DIGEST_BYTES],
        [0; SELECTABLE_DIGEST_BYTES],
    )?
    .encode()?;
    rejected_with_value[8] = 97;
    rejected_with_value.push(1);
    rejected_with_value[88] = 96;
    rejected_with_value[92] = 1;
    assert_eq!(
        SelectionReply::decode(&rejected_with_value),
        Err(SelectableProtocolError::UnexpectedRange {
            field: "selected_value"
        })
    );
    Ok(())
}

#[test]
fn selectable_bounds_reject_before_large_decode_allocations() -> Result<(), SelectableProtocolError>
{
    assert!(matches!(
        SelectionRequest::new(
            1,
            "choice",
            "instance",
            None,
            SELECTABLE_MESSAGE_MAX_BYTES + 1
        ),
        Err(SelectableProtocolError::MessageTooLarge { .. })
    ));
    assert!(matches!(
        SelectableRegister::new(
            1,
            "choice",
            vec![0; SELECTABLE_MESSAGE_MAX_BYTES],
            vec![1],
            Vec::new(),
        ),
        Err(SelectableProtocolError::MessageTooLarge { .. })
    ));

    let mut excessive_tags = register()?.encode()?;
    excessive_tags[52..54]
        .copy_from_slice(&((SELECTABLE_SEMANTIC_TAG_MAX_COUNT + 1) as u16).to_le_bytes());
    assert!(matches!(
        SelectableRegister::decode(&excessive_tags),
        Err(SelectableProtocolError::TooManySemanticTags { .. })
    ));
    Ok(())
}

#[test]
fn selection_request_optional_domain_flag_and_capacity_are_exact()
-> Result<(), SelectableProtocolError> {
    let plain = SelectionRequest::new(7, "choice", "instance", None, 128)?;
    let bytes = plain.encode()?;
    assert_eq!(&bytes[36..44], &[0; 8]);
    assert_eq!(&bytes[6..8], &[0; 2]);
    assert_eq!(SelectionRequest::decode(&bytes), Ok(plain));

    assert!(matches!(
        SelectionRequest::new(7, "choice", "instance", None, 95),
        Err(SelectableProtocolError::ReplyCapacityTooSmall { .. })
    ));
    assert_eq!(
        SelectionRequest::new(7, "choice", "instance", Some(Vec::new()), 128),
        Err(SelectableProtocolError::EmptyField {
            field: "narrowed_domain"
        })
    );
    Ok(())
}
