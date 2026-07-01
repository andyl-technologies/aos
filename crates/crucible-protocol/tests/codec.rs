//! Checks the pure protocol codec and frame stream helpers.

#![forbid(unsafe_code)]

use std::io::{Cursor, ErrorKind, Write};

use crucible_protocol::{
    ControlDirection, ControlTag, FRAME_LENGTH_PREFIX_SIZE, FrameDecodeError, FrameIoError,
    HostMsg, MAX_FRAME_SIZE, PluginMsg, TAG_HELLO, TAG_SETUP_ACK,
    WHITEBOX_DOORBELL_FRAME_HEADER_LEN, WHITEBOX_DOORBELL_FRAME_MAGIC,
    WHITEBOX_DOORBELL_PROTOCOL_VERSION, WhiteboxDoorbellFrame, WhiteboxDoorbellFrameDecodeError,
    WhiteboxDoorbellMarkerKind, WhiteboxMarkerPayload, WhiteboxMarkerPayloadDecodeError,
    WhiteboxMarkerPayloadEncodeError, WhiteboxRandomRequestBody, control_decode_host_msg,
    control_decode_plugin_msg, control_encode_host_msg, control_encode_plugin_msg,
    decode_whitebox_marker_payload, encode_whitebox_doorbell_frame,
    encode_whitebox_marker_payload_body, read_control_frame, write_control_frame,
};

#[test]
fn plugin_messages_round_trip_through_big_endian_frames() {
    assert_plugin_roundtrip(
        PluginMsg::Hello {
            proto_version: 2,
            abi_version: 1,
        },
        &[0, 0, 0, 9, 0xF0, 0, 0, 0, 2, 0, 0, 0, 1],
    );
    assert_plugin_roundtrip(PluginMsg::SetupAck { status: 0 }, &[0, 0, 0, 2, 0x02, 0]);
}

#[test]
fn host_messages_round_trip_through_big_endian_frames() {
    assert_host_roundtrip(
        HostMsg::HelloAck {
            proto_version: 2,
            abi_version: 1,
            slot_index: 7,
            node_count: 32,
        },
        &[
            0, 0, 0, 17, 0xF1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0, 32,
        ],
    );
    assert_host_roundtrip(
        HostMsg::Setup {
            region_len: 450_560,
        },
        &[0, 0, 0, 9, 0x01, 0, 0, 0, 0, 0, 6, 0xE0, 0],
    );
    assert_host_roundtrip(HostMsg::Quit, &[0, 0, 0, 1, 0x12]);
}

#[test]
fn decoder_reports_typed_frame_shape_errors() {
    assert_eq!(
        control_decode_plugin_msg(&[]),
        Err(FrameDecodeError::EmptyFrame)
    );
    assert_eq!(
        control_decode_plugin_msg(&[0, 0]),
        Err(FrameDecodeError::TruncatedLengthPrefix { actual: 2 })
    );
    assert_eq!(
        control_decode_plugin_msg(&[0, 0, 0, 65]),
        Err(FrameDecodeError::LengthExceedsMax {
            length: 65,
            max: MAX_FRAME_SIZE,
        })
    );
    assert_eq!(
        control_decode_plugin_msg(&[0, 0, 0, 2, TAG_HELLO]),
        Err(FrameDecodeError::TruncatedPayload {
            declared: 2,
            actual: 1,
        })
    );
    assert_eq!(
        control_decode_plugin_msg(&[0, 0, 0, 1, TAG_HELLO, 0]),
        Err(FrameDecodeError::TrailingBytes {
            declared: 1,
            actual: 2,
        })
    );
    assert_eq!(
        control_decode_plugin_msg(&[0, 0, 0, 0]),
        Err(FrameDecodeError::MissingTag)
    );
    assert_eq!(
        control_decode_plugin_msg(&[0, 0, 0, 1, 0x99]),
        Err(FrameDecodeError::UnknownTag { tag: 0x99 })
    );
}

#[test]
fn decoder_reports_direction_and_payload_shape_errors() {
    assert_eq!(
        control_decode_host_msg(&[0, 0, 0, 9, TAG_HELLO, 0, 0, 0, 2, 0, 0, 0, 1]),
        Err(FrameDecodeError::UnexpectedDirection {
            tag: ControlTag::Hello,
            expected: ControlDirection::HostToPlugin,
            actual: ControlDirection::PluginToHost,
        })
    );
    assert_eq!(
        control_decode_plugin_msg(&[0, 0, 0, 1, TAG_HELLO]),
        Err(FrameDecodeError::PayloadTooShort {
            tag: ControlTag::Hello,
            expected: 8,
            actual: 0,
        })
    );
    assert_eq!(
        control_decode_plugin_msg(&[0, 0, 0, 3, TAG_SETUP_ACK, 0, 1]),
        Err(FrameDecodeError::PayloadTooLong {
            tag: ControlTag::SetupAck,
            expected: 1,
            actual: 2,
        })
    );
}

#[test]
fn marker_payload_decoder_reports_typed_shape_errors() {
    let bad_flavor = marker_frame(WhiteboxDoorbellMarkerKind::Assertion, &[9, 1, 1]);
    assert_eq!(
        decode_whitebox_marker_payload(&bad_flavor),
        Err(WhiteboxMarkerPayloadDecodeError::InvalidAssertionFlavor { flavor: 9 })
    );

    let bad_bool = marker_frame(WhiteboxDoorbellMarkerKind::Assertion, &[0, 2, 1]);
    assert_eq!(
        decode_whitebox_marker_payload(&bad_bool),
        Err(WhiteboxMarkerPayloadDecodeError::InvalidBool {
            kind: WhiteboxDoorbellMarkerKind::Assertion,
            field: "condition",
            value: 2,
        })
    );

    let bad_random_width = marker_frame(
        WhiteboxDoorbellMarkerKind::RandomRequest,
        &[1, 0, 0, 0, 9, 0, 0],
    );
    assert_eq!(
        decode_whitebox_marker_payload(&bad_random_width),
        Err(WhiteboxMarkerPayloadDecodeError::InvalidRandomWidth {
            width_bytes: 9,
            max_width_bytes: 8,
        })
    );

    let short_stream_tag = marker_frame(
        WhiteboxDoorbellMarkerKind::RandomRequest,
        &[1, 0, 0, 0, 4, 3, 0, b'r'],
    );
    assert_eq!(
        decode_whitebox_marker_payload(&short_stream_tag),
        Err(
            WhiteboxMarkerPayloadDecodeError::LengthPrefixExceedsPayload {
                kind: WhiteboxDoorbellMarkerKind::RandomRequest,
                field: "stream_tag",
                declared_len: 3,
                remaining_len: 1,
            }
        )
    );

    let invalid_width_payload = WhiteboxMarkerPayload::RandomRequest(WhiteboxRandomRequestBody {
        request_id: 7,
        width_bytes: 0,
        stream_tag: String::from("rng"),
    });
    assert_eq!(
        encode_whitebox_marker_payload_body(&invalid_width_payload),
        Err(WhiteboxMarkerPayloadEncodeError::InvalidRandomWidth {
            width_bytes: 0,
            max_width_bytes: 8,
        })
    );
}

#[test]
fn doorbell_frame_decoder_reports_typed_shape_errors() {
    assert_eq!(
        WhiteboxDoorbellFrame::decode(&[1, 2, 3]),
        Err(WhiteboxDoorbellFrameDecodeError::TruncatedFrame {
            len: 3,
            minimum_len: WHITEBOX_DOORBELL_FRAME_HEADER_LEN,
        })
    );

    let bad_magic = doorbell_frame_with_header(0, WHITEBOX_DOORBELL_PROTOCOL_VERSION, 1, &[]);
    assert_eq!(
        WhiteboxDoorbellFrame::decode(&bad_magic),
        Err(WhiteboxDoorbellFrameDecodeError::BadMagic {
            expected: WHITEBOX_DOORBELL_FRAME_MAGIC,
            actual: 0,
        })
    );

    let bad_version = doorbell_frame_with_header(WHITEBOX_DOORBELL_FRAME_MAGIC, 0xffff, 1, &[]);
    assert_eq!(
        WhiteboxDoorbellFrame::decode(&bad_version),
        Err(WhiteboxDoorbellFrameDecodeError::UnsupportedVersion {
            expected: WHITEBOX_DOORBELL_PROTOCOL_VERSION,
            actual: 0xffff,
        })
    );

    let short_payload = doorbell_frame_with_declared_len(
        WHITEBOX_DOORBELL_FRAME_MAGIC,
        WHITEBOX_DOORBELL_PROTOCOL_VERSION,
        1,
        4,
        &[0xa5],
    );
    assert_eq!(
        WhiteboxDoorbellFrame::decode(&short_payload),
        Err(WhiteboxDoorbellFrameDecodeError::PayloadLengthMismatch {
            declared_len: 4,
            actual_len: 1,
        })
    );

    let oversized_declared = doorbell_frame_with_declared_len(
        WHITEBOX_DOORBELL_FRAME_MAGIC,
        WHITEBOX_DOORBELL_PROTOCOL_VERSION,
        1,
        9,
        &[],
    );
    assert_eq!(
        WhiteboxDoorbellFrame::decode_bounded(&oversized_declared, 8),
        Err(
            WhiteboxDoorbellFrameDecodeError::PayloadLengthExceedsBound {
                declared_len: 9,
                max_payload_len: 8,
            }
        )
    );
}

#[test]
fn frame_stream_helpers_reject_truncated_reads_as_io_errors() {
    let mut truncated_prefix = Cursor::new(vec![0, 0]);
    assert_eq!(
        read_control_frame(&mut truncated_prefix),
        Err(FrameIoError::TruncatedLengthPrefix)
    );

    let mut truncated_payload = Cursor::new(vec![0, 0, 0, 2, TAG_SETUP_ACK]);
    assert_eq!(
        read_control_frame(&mut truncated_payload),
        Err(FrameIoError::TruncatedPayload { length: 2 })
    );

    let mut oversized = Cursor::new(vec![0, 0, 0, 65]);
    assert_eq!(
        read_control_frame(&mut oversized),
        Err(FrameIoError::LengthExceedsMax {
            length: 65,
            max: MAX_FRAME_SIZE,
        })
    );
}

#[test]
fn frame_stream_helpers_read_and_write_complete_frames() {
    let frame = control_encode_host_msg(&HostMsg::Quit);
    let mut reader = Cursor::new(frame.clone());
    assert_eq!(must_read_frame(&mut reader), frame);

    let mut writer = Vec::new();
    assert_eq!(write_control_frame(&mut writer, &frame), Ok(()));
    assert_eq!(writer, frame);
}

#[test]
fn frame_stream_helpers_report_write_errors() {
    let frame = control_encode_host_msg(&HostMsg::Quit);
    let mut writer = FailingWriter;
    assert_eq!(
        write_control_frame(&mut writer, &frame),
        Err(FrameIoError::Io {
            operation: "write control frame",
            kind: ErrorKind::BrokenPipe,
        })
    );

    let mut writer = FailingFlushWriter;
    assert_eq!(
        write_control_frame(&mut writer, &frame),
        Err(FrameIoError::Io {
            operation: "flush control frame",
            kind: ErrorKind::ConnectionReset,
        })
    );
}

#[test]
fn frame_read_helper_preserves_prefix_and_length_contract() {
    let frame = control_encode_plugin_msg(&PluginMsg::SetupAck { status: 7 });
    let mut reader = Cursor::new(frame.clone());
    let read = must_read_frame(&mut reader);
    assert_eq!(read.len(), FRAME_LENGTH_PREFIX_SIZE + 2);
    assert_eq!(read, frame);
}

fn assert_plugin_roundtrip(message: PluginMsg, expected: &[u8]) {
    let encoded = control_encode_plugin_msg(&message);
    assert_eq!(encoded, expected);
    assert_eq!(control_decode_plugin_msg(&encoded), Ok(message));
}

fn assert_host_roundtrip(message: HostMsg, expected: &[u8]) {
    let encoded = control_encode_host_msg(&message);
    assert_eq!(encoded, expected);
    assert_eq!(control_decode_host_msg(&encoded), Ok(message));
}

fn must_read_frame<R>(reader: &mut R) -> Vec<u8>
where
    R: std::io::Read,
{
    match read_control_frame(reader) {
        Ok(frame) => frame,
        Err(error) => panic!("frame read should succeed: {error}"),
    }
}

fn marker_frame(kind: WhiteboxDoorbellMarkerKind, payload: &[u8]) -> WhiteboxDoorbellFrame {
    let frame = match encode_whitebox_doorbell_frame(kind.wire_value(), payload) {
        Ok(frame) => frame,
        Err(error) => panic!("marker test frame should encode: {error}"),
    };
    match WhiteboxDoorbellFrame::decode(&frame) {
        Ok(frame) => frame,
        Err(error) => panic!("marker test frame should decode: {error}"),
    }
}

fn doorbell_frame_with_header(magic: u32, version: u16, kind: u16, body: &[u8]) -> Vec<u8> {
    doorbell_frame_with_declared_len(magic, version, kind, body.len() as u32, body)
}

fn doorbell_frame_with_declared_len(
    magic: u32,
    version: u16,
    kind: u16,
    declared_len: u32,
    body: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&magic.to_le_bytes());
    frame.extend_from_slice(&version.to_le_bytes());
    frame.extend_from_slice(&kind.to_le_bytes());
    frame.extend_from_slice(&declared_len.to_le_bytes());
    frame.extend_from_slice(body);
    frame
}

struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from(ErrorKind::BrokenPipe))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct FailingFlushWriter;

impl Write for FailingFlushWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::from(ErrorKind::ConnectionReset))
    }
}
