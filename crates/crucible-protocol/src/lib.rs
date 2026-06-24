//! `crucible-protocol` owns the host/plugin wire protocol.
//!
//! Spec index: RFC-0010 files 14.
//!
//! This L1 crate owns the framed IPC message constants, version fields,
//! encode/decode routines, and golden vectors specified by its indexed RFC-0010
//! file. It operates over owned buffers and does not own the shared-memory
//! transport or scheduler semantics.
//!
//! Module map: the crate root owns the frame-format constants, closed tag
//! registry, message bodies, pure codec, frame I/O helpers, and control/data
//! split contract. Future modules will split descriptor passing, handshake
//! orchestration, and golden vectors.
//!
//! Wire-format:
//!
//! ```text
//! offset  size  field
//! 0       4     length: u32 big-endian, counting tag + payload bytes
//! 4       1     tag: u8 from the closed ControlTag registry
//! 5       N     payload bytes, tag-specific and big-endian for integers
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

use std::io::{ErrorKind, Read, Write};

use thiserror::Error;

/// Number of bytes in the big-endian frame-length prefix.
pub const FRAME_LENGTH_PREFIX_SIZE: usize = 4;
/// Number of bytes in the frame tag field.
pub const FRAME_TAG_SIZE: usize = 1;
/// Maximum value accepted in the frame-length prefix.
///
/// The length prefix counts the bytes that follow the prefix: one tag byte plus
/// the tag-specific payload bytes.
pub const MAX_FRAME_SIZE: u32 = 64;
/// Maximum payload bytes a single control frame can carry.
pub const MAX_PAYLOAD_SIZE: u32 = MAX_FRAME_SIZE - FRAME_TAG_SIZE as u32;
/// Whether the frame-length prefix counts the tag byte.
pub const FRAME_LENGTH_INCLUDES_TAG: bool = true;
/// Whether all multi-byte integers in frame payloads use big-endian order.
pub const FRAME_INTEGERS_ARE_BIG_ENDIAN: bool = true;

/// Direction in which a control-frame tag may appear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlDirection {
    /// The host sends this tag to the QEMU plugin.
    HostToPlugin,
    /// The QEMU plugin sends this tag to the host.
    PluginToHost,
}

/// Closed registry of host/plugin control-frame tags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ControlTag {
    /// Host-to-plugin setup frame carrying the shared-memory region length.
    Setup = 0x01,
    /// Plugin-to-host setup acknowledgement frame.
    SetupAck = 0x02,
    /// Host-to-plugin graceful shutdown request.
    Quit = 0x12,
    /// Plugin-to-host handshake offer.
    Hello = 0xF0,
    /// Host-to-plugin handshake acknowledgement.
    HelloAck = 0xF1,
}

/// Setup frame tag value.
pub const TAG_SETUP: u8 = ControlTag::Setup.wire_value();
/// SetupAck frame tag value.
pub const TAG_SETUP_ACK: u8 = ControlTag::SetupAck.wire_value();
/// Quit frame tag value.
pub const TAG_QUIT: u8 = ControlTag::Quit.wire_value();
/// Hello frame tag value.
pub const TAG_HELLO: u8 = ControlTag::Hello.wire_value();
/// HelloAck frame tag value.
pub const TAG_HELLO_ACK: u8 = ControlTag::HelloAck.wire_value();
/// All valid control tags in stable registry order.
pub const ALL_CONTROL_TAGS: [ControlTag; 5] = [
    ControlTag::Setup,
    ControlTag::SetupAck,
    ControlTag::Quit,
    ControlTag::Hello,
    ControlTag::HelloAck,
];

impl ControlTag {
    /// Returns the byte value carried in the frame tag field.
    #[must_use]
    pub const fn wire_value(self) -> u8 {
        self as u8
    }

    /// Returns the only valid direction for this tag.
    #[must_use]
    pub const fn direction(self) -> ControlDirection {
        match self {
            Self::Setup | Self::Quit | Self::HelloAck => ControlDirection::HostToPlugin,
            Self::SetupAck | Self::Hello => ControlDirection::PluginToHost,
        }
    }

    /// Returns the fixed payload length for this tag.
    #[must_use]
    pub const fn payload_len(self) -> usize {
        match self {
            Self::Setup => 8,
            Self::SetupAck => 1,
            Self::Quit => 0,
            Self::Hello => 8,
            Self::HelloAck => 16,
        }
    }

    /// Returns the closed-registry tag for `value`.
    #[must_use]
    pub const fn from_wire_value(value: u8) -> Option<Self> {
        match value {
            TAG_SETUP => Some(Self::Setup),
            TAG_SETUP_ACK => Some(Self::SetupAck),
            TAG_QUIT => Some(Self::Quit),
            TAG_HELLO => Some(Self::Hello),
            TAG_HELLO_ACK => Some(Self::HelloAck),
            _ => None,
        }
    }
}

/// Plugin-to-host control messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PluginMsg {
    /// Handshake offer sent before the plugin touches shared memory.
    Hello {
        /// Highest control-protocol version the plugin can speak.
        proto_version: u32,
        /// Shared-memory ABI version the plugin was built against.
        abi_version: u32,
    },
    /// Setup completion acknowledgement.
    SetupAck {
        /// Zero means ready; any nonzero value means setup failed.
        status: u8,
    },
}

/// Host-to-plugin control messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostMsg {
    /// Handshake acknowledgement carrying the negotiated versions and slot.
    HelloAck {
        /// Negotiated control-protocol version.
        proto_version: u32,
        /// Host shared-memory ABI version.
        abi_version: u32,
        /// Zero-based shared-memory node slot assigned to this plugin.
        slot_index: u32,
        /// Number of node slots in the shared-memory region.
        node_count: u32,
    },
    /// Setup frame carrying the region byte length.
    Setup {
        /// Total byte length of the shared-memory region to map.
        region_len: u64,
    },
    /// Graceful shutdown request.
    Quit,
}

/// Typed errors returned by pure control-frame decoding.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FrameDecodeError {
    /// The byte buffer is empty.
    #[error("control frame is empty")]
    EmptyFrame,
    /// The buffer does not contain the full four-byte length prefix.
    #[error("control frame length prefix is truncated: actual {actual} bytes")]
    TruncatedLengthPrefix {
        /// Number of bytes available for the length prefix.
        actual: usize,
    },
    /// The decoded length exceeds [`MAX_FRAME_SIZE`].
    #[error("control frame length {length} exceeds maximum {max}")]
    LengthExceedsMax {
        /// Decoded frame length, counting tag plus payload bytes.
        length: u32,
        /// Maximum permitted frame length, counting tag plus payload bytes.
        max: u32,
    },
    /// The frame declares more bytes than the supplied buffer contains.
    #[error("control frame payload is truncated: declared {declared} bytes, actual {actual} bytes")]
    TruncatedPayload {
        /// Declared length, counting tag plus payload bytes.
        declared: usize,
        /// Actual bytes after the length prefix.
        actual: usize,
    },
    /// The supplied buffer contains bytes beyond the declared frame.
    #[error("control frame has trailing bytes: declared {declared} bytes, actual {actual} bytes")]
    TrailingBytes {
        /// Declared length, counting tag plus payload bytes.
        declared: usize,
        /// Actual bytes after the length prefix.
        actual: usize,
    },
    /// The frame has a zero length and therefore no tag byte.
    #[error("control frame is missing its tag byte")]
    MissingTag,
    /// The tag byte is not in the closed registry.
    #[error("unknown control frame tag 0x{tag:02x}")]
    UnknownTag {
        /// Unregistered tag byte.
        tag: u8,
    },
    /// The tag is valid but belongs to the other protocol direction.
    #[error("control frame tag {tag:?} has direction {actual:?}, expected {expected:?}")]
    UnexpectedDirection {
        /// Decoded tag.
        tag: ControlTag,
        /// Direction required by the selected decoder.
        expected: ControlDirection,
        /// Direction registered for the decoded tag.
        actual: ControlDirection,
    },
    /// The tag-specific payload is shorter than the registered shape.
    #[error(
        "control frame tag {tag:?} payload is too short: expected {expected} bytes, actual {actual} bytes"
    )]
    PayloadTooShort {
        /// Decoded tag.
        tag: ControlTag,
        /// Required payload byte length.
        expected: usize,
        /// Actual payload byte length.
        actual: usize,
    },
    /// The tag-specific payload is longer than the registered shape.
    #[error(
        "control frame tag {tag:?} payload is too long: expected {expected} bytes, actual {actual} bytes"
    )]
    PayloadTooLong {
        /// Decoded tag.
        tag: ControlTag,
        /// Required payload byte length.
        expected: usize,
        /// Actual payload byte length.
        actual: usize,
    },
}

/// Typed errors returned by frame stream read/write helpers.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum FrameIoError {
    /// The stream ended before a complete four-byte length prefix arrived.
    #[error("control frame stream ended during length prefix")]
    TruncatedLengthPrefix,
    /// The decoded length exceeds [`MAX_FRAME_SIZE`].
    #[error("control frame length {length} exceeds maximum {max}")]
    LengthExceedsMax {
        /// Decoded frame length, counting tag plus payload bytes.
        length: u32,
        /// Maximum permitted frame length, counting tag plus payload bytes.
        max: u32,
    },
    /// The stream ended before the declared frame payload arrived.
    #[error("control frame stream ended during payload of {length} bytes")]
    TruncatedPayload {
        /// Declared length, counting tag plus payload bytes.
        length: u32,
    },
    /// The underlying stream returned a non-EOF I/O error.
    #[error("{operation} failed with {kind:?}")]
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Error kind returned by the stream.
        kind: ErrorKind,
    },
}

/// Encodes a plugin-to-host control message as a complete frame.
#[must_use]
pub fn control_encode_plugin_msg(message: &PluginMsg) -> Vec<u8> {
    match message {
        PluginMsg::Hello {
            proto_version,
            abi_version,
        } => encode_frame(
            ControlTag::Hello,
            &[
                FieldValue::U32(*proto_version),
                FieldValue::U32(*abi_version),
            ],
        ),
        PluginMsg::SetupAck { status } => {
            encode_frame(ControlTag::SetupAck, &[FieldValue::U8(*status)])
        }
    }
}

/// Decodes a complete plugin-to-host control frame.
///
/// # Errors
///
/// Returns [`FrameDecodeError`] when the frame bytes are empty, truncated,
/// oversized, tagged with an unknown or wrong-direction tag, or carry a payload
/// length that does not match the tag registry.
pub fn control_decode_plugin_msg(frame: &[u8]) -> Result<PluginMsg, FrameDecodeError> {
    let decoded = decode_frame(frame, ControlDirection::PluginToHost)?;
    match decoded.tag {
        ControlTag::Hello => Ok(PluginMsg::Hello {
            proto_version: read_u32_be(decoded.payload, 0),
            abi_version: read_u32_be(decoded.payload, 4),
        }),
        ControlTag::SetupAck => Ok(PluginMsg::SetupAck {
            status: decoded.payload[0],
        }),
        ControlTag::Setup | ControlTag::Quit | ControlTag::HelloAck => {
            Err(FrameDecodeError::UnexpectedDirection {
                tag: decoded.tag,
                expected: ControlDirection::PluginToHost,
                actual: decoded.tag.direction(),
            })
        }
    }
}

/// Encodes a host-to-plugin control message as a complete frame.
#[must_use]
pub fn control_encode_host_msg(message: &HostMsg) -> Vec<u8> {
    match message {
        HostMsg::HelloAck {
            proto_version,
            abi_version,
            slot_index,
            node_count,
        } => encode_frame(
            ControlTag::HelloAck,
            &[
                FieldValue::U32(*proto_version),
                FieldValue::U32(*abi_version),
                FieldValue::U32(*slot_index),
                FieldValue::U32(*node_count),
            ],
        ),
        HostMsg::Setup { region_len } => {
            encode_frame(ControlTag::Setup, &[FieldValue::U64(*region_len)])
        }
        HostMsg::Quit => encode_frame(ControlTag::Quit, &[]),
    }
}

/// Decodes a complete host-to-plugin control frame.
///
/// # Errors
///
/// Returns [`FrameDecodeError`] when the frame bytes are empty, truncated,
/// oversized, tagged with an unknown or wrong-direction tag, or carry a payload
/// length that does not match the tag registry.
pub fn control_decode_host_msg(frame: &[u8]) -> Result<HostMsg, FrameDecodeError> {
    let decoded = decode_frame(frame, ControlDirection::HostToPlugin)?;
    match decoded.tag {
        ControlTag::HelloAck => Ok(HostMsg::HelloAck {
            proto_version: read_u32_be(decoded.payload, 0),
            abi_version: read_u32_be(decoded.payload, 4),
            slot_index: read_u32_be(decoded.payload, 8),
            node_count: read_u32_be(decoded.payload, 12),
        }),
        ControlTag::Setup => Ok(HostMsg::Setup {
            region_len: read_u64_be(decoded.payload, 0),
        }),
        ControlTag::Quit => Ok(HostMsg::Quit),
        ControlTag::SetupAck | ControlTag::Hello => Err(FrameDecodeError::UnexpectedDirection {
            tag: decoded.tag,
            expected: ControlDirection::HostToPlugin,
            actual: decoded.tag.direction(),
        }),
    }
}

/// Reads one complete length-prefixed control frame from `reader`.
///
/// # Errors
///
/// Returns [`FrameIoError::TruncatedLengthPrefix`] or
/// [`FrameIoError::TruncatedPayload`] when the stream ends mid-frame,
/// [`FrameIoError::LengthExceedsMax`] before allocating an oversized payload, or
/// [`FrameIoError::Io`] for other stream errors.
pub fn read_control_frame<R>(reader: &mut R) -> Result<Vec<u8>, FrameIoError>
where
    R: Read,
{
    let mut length_prefix = [0; FRAME_LENGTH_PREFIX_SIZE];
    reader
        .read_exact(&mut length_prefix)
        .map_err(|error| match error.kind() {
            ErrorKind::UnexpectedEof => FrameIoError::TruncatedLengthPrefix,
            kind => FrameIoError::Io {
                operation: "read control-frame length prefix",
                kind,
            },
        })?;
    let length = u32::from_be_bytes(length_prefix);
    if length > MAX_FRAME_SIZE {
        return Err(FrameIoError::LengthExceedsMax {
            length,
            max: MAX_FRAME_SIZE,
        });
    }

    let payload_len = length as usize;
    let mut frame = Vec::with_capacity(FRAME_LENGTH_PREFIX_SIZE + payload_len);
    frame.extend_from_slice(&length_prefix);
    frame.resize(FRAME_LENGTH_PREFIX_SIZE + payload_len, 0);
    reader
        .read_exact(&mut frame[FRAME_LENGTH_PREFIX_SIZE..])
        .map_err(|error| match error.kind() {
            ErrorKind::UnexpectedEof => FrameIoError::TruncatedPayload { length },
            kind => FrameIoError::Io {
                operation: "read control-frame payload",
                kind,
            },
        })?;

    Ok(frame)
}

/// Writes a complete control frame to `writer`.
///
/// # Errors
///
/// Returns [`FrameIoError::Io`] when the underlying writer rejects the frame.
pub fn write_control_frame<W>(writer: &mut W, frame: &[u8]) -> Result<(), FrameIoError>
where
    W: Write,
{
    writer.write_all(frame).map_err(|error| FrameIoError::Io {
        operation: "write control frame",
        kind: error.kind(),
    })
}

/// The runtime data plane used after protocol setup completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeDataPlane {
    /// Runtime delivery uses the shared-memory region, not control frames.
    SharedMemory,
}

/// The control/data split required for deterministic runtime injection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeDataPlaneContract {
    /// The transport that carries runtime frame and clock data.
    pub runtime_data_plane: RuntimeDataPlane,
    /// Whether the control channel carries runtime frame payloads.
    pub control_channel_carries_runtime_frames: bool,
    /// Whether the control channel carries frame delivery icounts.
    pub control_channel_carries_delivery_icounts: bool,
    /// Whether the control channel is silent between setup completion and quit.
    pub control_channel_silent_between_setup_ack_and_quit: bool,
}

/// The protocol-level Contract B boundary.
pub const RUNTIME_DATA_PLANE_CONTRACT: RuntimeDataPlaneContract = RuntimeDataPlaneContract {
    runtime_data_plane: RuntimeDataPlane::SharedMemory,
    control_channel_carries_runtime_frames: false,
    control_channel_carries_delivery_icounts: false,
    control_channel_silent_between_setup_ack_and_quit: true,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DecodedFrame<'a> {
    tag: ControlTag,
    payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FieldValue {
    U8(u8),
    U32(u32),
    U64(u64),
}

fn encode_frame(tag: ControlTag, fields: &[FieldValue]) -> Vec<u8> {
    let payload_len: usize = fields
        .iter()
        .map(|field| match field {
            FieldValue::U8(_) => 1,
            FieldValue::U32(_) => 4,
            FieldValue::U64(_) => 8,
        })
        .sum();
    debug_assert_eq!(payload_len, tag.payload_len());
    debug_assert!(FRAME_TAG_SIZE + payload_len <= MAX_FRAME_SIZE as usize);

    let frame_len = FRAME_TAG_SIZE + payload_len;
    let mut frame = Vec::with_capacity(FRAME_LENGTH_PREFIX_SIZE + frame_len);
    frame.extend_from_slice(&(frame_len as u32).to_be_bytes());
    frame.push(tag.wire_value());
    for field in fields {
        match field {
            FieldValue::U8(value) => frame.push(*value),
            FieldValue::U32(value) => frame.extend_from_slice(&value.to_be_bytes()),
            FieldValue::U64(value) => frame.extend_from_slice(&value.to_be_bytes()),
        }
    }
    frame
}

fn decode_frame(
    frame: &[u8],
    expected_direction: ControlDirection,
) -> Result<DecodedFrame<'_>, FrameDecodeError> {
    if frame.is_empty() {
        return Err(FrameDecodeError::EmptyFrame);
    }
    if frame.len() < FRAME_LENGTH_PREFIX_SIZE {
        return Err(FrameDecodeError::TruncatedLengthPrefix {
            actual: frame.len(),
        });
    }

    let declared = read_u32_be(frame, 0);
    if declared > MAX_FRAME_SIZE {
        return Err(FrameDecodeError::LengthExceedsMax {
            length: declared,
            max: MAX_FRAME_SIZE,
        });
    }

    let declared = declared as usize;
    let actual = frame.len() - FRAME_LENGTH_PREFIX_SIZE;
    if actual < declared {
        return Err(FrameDecodeError::TruncatedPayload { declared, actual });
    }
    if actual > declared {
        return Err(FrameDecodeError::TrailingBytes { declared, actual });
    }
    if declared == 0 {
        return Err(FrameDecodeError::MissingTag);
    }

    let tag_byte = frame[FRAME_LENGTH_PREFIX_SIZE];
    let tag = ControlTag::from_wire_value(tag_byte)
        .ok_or(FrameDecodeError::UnknownTag { tag: tag_byte })?;
    let actual_direction = tag.direction();
    if actual_direction != expected_direction {
        return Err(FrameDecodeError::UnexpectedDirection {
            tag,
            expected: expected_direction,
            actual: actual_direction,
        });
    }

    let payload = &frame[FRAME_LENGTH_PREFIX_SIZE + FRAME_TAG_SIZE..];
    let expected_payload_len = tag.payload_len();
    if payload.len() < expected_payload_len {
        return Err(FrameDecodeError::PayloadTooShort {
            tag,
            expected: expected_payload_len,
            actual: payload.len(),
        });
    }
    if payload.len() > expected_payload_len {
        return Err(FrameDecodeError::PayloadTooLong {
            tag,
            expected: expected_payload_len,
            actual: payload.len(),
        });
    }

    Ok(DecodedFrame { tag, payload })
}

fn read_u32_be(bytes: &[u8], offset: usize) -> u32 {
    let mut out = [0; 4];
    out.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_be_bytes(out)
}

fn read_u64_be(bytes: &[u8], offset: usize) -> u64 {
    let mut out = [0; 8];
    out.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_be_bytes(out)
}
