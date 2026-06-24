//! Checks the pure protocol codec and frame stream helpers.

#![forbid(unsafe_code)]

use std::io::{Cursor, ErrorKind, Write};

use crucible_protocol::{
    ControlDirection, ControlTag, FRAME_LENGTH_PREFIX_SIZE, FrameDecodeError, FrameIoError,
    HostMsg, MAX_FRAME_SIZE, PluginMsg, TAG_HELLO, TAG_SETUP_ACK, control_decode_host_msg,
    control_decode_plugin_msg, control_encode_host_msg, control_encode_plugin_msg,
    read_control_frame, write_control_frame,
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
