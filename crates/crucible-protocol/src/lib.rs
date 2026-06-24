//! `crucible-protocol` owns the host/plugin wire protocol.
//!
//! Spec index: RFC-0010 files 14.
//!
//! This L1 crate owns the framed IPC message constants, version fields,
//! encode/decode routines, and golden vectors specified by its indexed RFC-0010
//! file. Its pure codec operates over owned buffers; its Unix descriptor
//! handover attaches the shared-memory and wake descriptors to the setup frame.
//!
//! Module map: the crate root owns the frame-format constants, closed tag
//! registry, message bodies, pure codec, frame I/O helpers, handshake
//! orchestration, setup descriptor passing, and control/data split contract.
//! Future modules will split golden vectors.
//!
//! Unsafe boundary discipline: raw `sendmsg`/`recvmsg` and ancillary-buffer
//! details stay private; public callers use safe setup descriptor handover wrappers.
//! These validate the fixed two-fd order and descriptor count before exposing
//! owned close-on-exec descriptors.
//!
//! Wire-format:
//!
//! ```text
//! offset  size  field
//! 0       4     length: u32 big-endian, counting tag + payload bytes
//! 4       1     tag: u8 from the closed ControlTag registry
//! 5       N     payload bytes, tag-specific and big-endian for integers
//! ```

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

use std::io::{ErrorKind, Read, Write};
#[cfg(unix)]
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

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
/// Lowest control-protocol version this crate can negotiate.
pub const CONTROL_PROTOCOL_MIN_VERSION: u32 = 1;
/// Highest control-protocol version this crate can negotiate.
pub const CONTROL_PROTOCOL_VERSION: u32 = 1;

#[cfg(unix)]
const SETUP_DESCRIPTOR_RECV_CAPACITY: usize = SETUP_DESCRIPTOR_COUNT + 1;
#[cfg(unix)]
const ANCILLARY_STORAGE_HEADERS: usize = 8;
#[cfg(all(
    unix,
    any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "watchos"
    )
))]
type MsgControlLen = libc::socklen_t;
#[cfg(all(
    unix,
    not(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "watchos"
    ))
))]
type MsgControlLen = usize;

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

/// Number of file descriptors attached to a `Setup` frame.
#[cfg(unix)]
pub const SETUP_DESCRIPTOR_COUNT: usize = 2;

/// Borrowed descriptors attached to an outbound `Setup` frame.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupDescriptorFds {
    /// Shared-memory region descriptor, sent first in the `SCM_RIGHTS` list.
    pub shmem_fd: RawFd,
    /// Wake descriptor, sent second in the `SCM_RIGHTS` list.
    pub wake_fd: RawFd,
}

/// Owned descriptors received from an inbound `Setup` frame.
#[cfg(unix)]
#[derive(Debug)]
pub struct ReceivedSetupDescriptors {
    /// Shared-memory region descriptor received first in the `SCM_RIGHTS` list.
    pub shmem_fd: OwnedFd,
    /// Wake descriptor received second in the `SCM_RIGHTS` list.
    pub wake_fd: OwnedFd,
}

/// A decoded `Setup` frame plus its attached descriptors.
#[cfg(unix)]
#[derive(Debug)]
pub struct ReceivedSetup {
    /// Total byte length of the shared-memory region to map.
    pub region_len: u64,
    /// Fixed-order descriptors attached to the setup frame.
    pub descriptors: ReceivedSetupDescriptors,
}

/// Host-side inputs used to accept the initial `Hello` handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostHandshakeConfig {
    /// Highest control-protocol version supported by the host.
    pub proto_version: u32,
    /// Shared-memory ABI version used to build the region.
    pub abi_version: u32,
    /// Zero-based shared-memory slot assigned to this plugin.
    pub slot_index: u32,
    /// Total number of slots in the shared-memory region.
    pub node_count: u32,
}

/// Plugin-side inputs used to start the initial `Hello` handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginHandshakeConfig {
    /// Highest control-protocol version supported by the plugin.
    pub proto_version: u32,
    /// Shared-memory ABI version compiled into the plugin.
    pub abi_version: u32,
}

/// A successful `Hello`/`HelloAck` negotiation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NegotiatedHandshake {
    /// Single negotiated control-protocol version both peers must speak.
    pub proto_version: u32,
    /// Shared-memory ABI version both peers agreed on exactly.
    pub abi_version: u32,
    /// Zero-based shared-memory slot assigned to this plugin.
    pub slot_index: u32,
    /// Total number of slots in the shared-memory region.
    pub node_count: u32,
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

/// Typed errors returned by the initial protocol handshake.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum HandshakeError {
    /// A control-frame read or write failed.
    #[error("handshake I/O failed")]
    Io {
        /// Underlying frame I/O error.
        source: FrameIoError,
    },
    /// A handshake frame failed byte-level decoding.
    #[error("handshake frame decode failed")]
    Decode {
        /// Underlying frame decode error.
        source: FrameDecodeError,
    },
    /// The decoded frame had the wrong direction or message kind.
    #[error("unexpected handshake message: {message:?}")]
    UnexpectedPluginMessage {
        /// Decoded plugin-to-host message.
        message: PluginMsg,
    },
    /// The decoded frame had the wrong direction or message kind.
    #[error("unexpected handshake message: {message:?}")]
    UnexpectedHostMessage {
        /// Decoded host-to-plugin message.
        message: HostMsg,
    },
    /// Host and plugin protocol-version ranges do not overlap.
    #[error(
        "no control-protocol version overlap: plugin max {plugin_max}, host range {host_min}..={host_max}"
    )]
    ProtocolVersionNoOverlap {
        /// Highest control-protocol version offered by the plugin.
        plugin_max: u32,
        /// Lowest control-protocol version supported by the host.
        host_min: u32,
        /// Highest control-protocol version supported by the host.
        host_max: u32,
    },
    /// The host replied with a protocol version the plugin cannot speak.
    #[error(
        "negotiated control-protocol version {negotiated} is outside plugin range {plugin_min}..={plugin_max}"
    )]
    NegotiatedProtocolOutOfRange {
        /// Protocol version sent in `HelloAck`.
        negotiated: u32,
        /// Lowest control-protocol version supported by the plugin.
        plugin_min: u32,
        /// Highest control-protocol version offered by the plugin.
        plugin_max: u32,
    },
    /// Host and plugin shmem ABI versions differ.
    #[error("shared-memory ABI mismatch: plugin {plugin_abi}, host {host_abi}")]
    AbiMismatch {
        /// ABI version offered by the plugin.
        plugin_abi: u32,
        /// ABI version required by the host.
        host_abi: u32,
    },
    /// The host assigned a slot outside the declared node range.
    #[error("assigned slot {slot_index} is outside node_count {node_count}")]
    InvalidSlot {
        /// Slot index carried in `HelloAck`.
        slot_index: u32,
        /// Node count carried in `HelloAck`.
        node_count: u32,
    },
}

/// Typed errors returned by Unix setup descriptor handover.
#[cfg(unix)]
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DescriptorHandoverError {
    /// A syscall returned an OS error.
    #[error("{operation} failed with errno {errno}")]
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Raw `errno` value reported by the OS.
        errno: i32,
    },
    /// The peer closed the socket before a complete setup frame arrived.
    #[error("{operation} ended before setup completed")]
    PeerClosed {
        /// Operation being attempted.
        operation: &'static str,
    },
    /// `sendmsg` accepted fewer bytes than the complete setup frame.
    #[error("setup sendmsg wrote {actual} bytes, expected {expected}")]
    ShortWrite {
        /// Complete setup frame byte length.
        expected: usize,
        /// Bytes reported by `sendmsg`.
        actual: usize,
    },
    /// The received setup frame failed byte-level decoding.
    #[error("setup frame decode failed")]
    Decode {
        /// Underlying frame decode error.
        source: FrameDecodeError,
    },
    /// The frame decoded successfully but was not a `Setup` message.
    #[error("expected Setup frame, received {message:?}")]
    UnexpectedMessage {
        /// Decoded host-to-plugin message.
        message: HostMsg,
    },
    /// The setup frame carried the wrong descriptor count.
    #[error("setup frame carried {count} descriptors, expected 2")]
    WrongDescriptorCount {
        /// Number of descriptors received with the setup frame.
        count: usize,
    },
    /// The ancillary data was truncated by the kernel.
    #[error("setup SCM_RIGHTS ancillary data was truncated")]
    AncillaryTruncated,
    /// The ancillary data could not be parsed as whole file descriptors.
    #[error("setup SCM_RIGHTS ancillary data is malformed: {reason}")]
    MalformedAncillary {
        /// Short reason for the parse failure.
        reason: &'static str,
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

/// Writes and flushes a complete control frame to `writer`.
///
/// # Errors
///
/// Returns [`FrameIoError::Io`] when the underlying writer rejects the frame or
/// flush.
pub fn write_control_frame<W>(writer: &mut W, frame: &[u8]) -> Result<(), FrameIoError>
where
    W: Write,
{
    writer.write_all(frame).map_err(|error| FrameIoError::Io {
        operation: "write control frame",
        kind: error.kind(),
    })?;
    writer.flush().map_err(|error| FrameIoError::Io {
        operation: "flush control frame",
        kind: error.kind(),
    })
}

/// Runs the host side of the blocking `Hello`/`HelloAck` handshake.
///
/// This reads one plugin `Hello`, negotiates
/// `min(plugin.proto_version, config.proto_version)`, checks the shmem ABI
/// version exactly, validates the assigned slot, writes `HelloAck`, and returns
/// the negotiated values.
///
/// # Errors
///
/// Returns [`HandshakeError`] when the frame cannot be read, decoded, or
/// written; when the first plugin message is not `Hello`; when protocol
/// versions do not overlap; when the shmem ABI version differs; or when
/// `slot_index >= node_count`.
pub fn host_accept_handshake<S>(
    stream: &mut S,
    config: HostHandshakeConfig,
) -> Result<NegotiatedHandshake, HandshakeError>
where
    S: Read + Write,
{
    let frame = read_control_frame(stream).map_err(|source| HandshakeError::Io { source })?;
    let message =
        control_decode_plugin_msg(&frame).map_err(|source| HandshakeError::Decode { source })?;
    let negotiated = host_negotiate_handshake(message, config)?;
    let ack = HostMsg::HelloAck {
        proto_version: negotiated.proto_version,
        abi_version: negotiated.abi_version,
        slot_index: negotiated.slot_index,
        node_count: negotiated.node_count,
    };
    let ack = control_encode_host_msg(&ack);
    write_control_frame(stream, &ack).map_err(|source| HandshakeError::Io { source })?;
    Ok(negotiated)
}

/// Runs the plugin side of the blocking `Hello`/`HelloAck` handshake.
///
/// This writes `Hello`, blocks for one host `HelloAck`, checks that the
/// negotiated protocol version remains within the plugin-supported range,
/// checks the shmem ABI version exactly, validates `slot_index < node_count`,
/// and returns the negotiated values.
///
/// # Errors
///
/// Returns [`HandshakeError`] when the frame cannot be written, read, or
/// decoded; when the host reply is not `HelloAck`; when the negotiated protocol
/// version is outside the plugin's range; when the shmem ABI version differs;
/// or when `slot_index >= node_count`.
pub fn plugin_start_handshake<S>(
    stream: &mut S,
    config: PluginHandshakeConfig,
) -> Result<NegotiatedHandshake, HandshakeError>
where
    S: Read + Write,
{
    let hello = PluginMsg::Hello {
        proto_version: config.proto_version,
        abi_version: config.abi_version,
    };
    let hello = control_encode_plugin_msg(&hello);
    write_control_frame(stream, &hello).map_err(|source| HandshakeError::Io { source })?;

    let frame = read_control_frame(stream).map_err(|source| HandshakeError::Io { source })?;
    let message =
        control_decode_host_msg(&frame).map_err(|source| HandshakeError::Decode { source })?;
    plugin_validate_handshake_ack(message, config)
}

/// Negotiates a host-side `Hello` message without performing I/O.
///
/// # Errors
///
/// Returns [`HandshakeError`] when `message` is not `Hello`, when the protocol
/// versions do not overlap, when the shmem ABI version differs, or when the
/// host slot assignment is outside the declared node range.
pub fn host_negotiate_handshake(
    message: PluginMsg,
    config: HostHandshakeConfig,
) -> Result<NegotiatedHandshake, HandshakeError> {
    let PluginMsg::Hello {
        proto_version: plugin_proto_version,
        abi_version: plugin_abi_version,
    } = message
    else {
        return Err(HandshakeError::UnexpectedPluginMessage { message });
    };

    if plugin_proto_version < CONTROL_PROTOCOL_MIN_VERSION
        || config.proto_version < CONTROL_PROTOCOL_MIN_VERSION
    {
        return Err(HandshakeError::ProtocolVersionNoOverlap {
            plugin_max: plugin_proto_version,
            host_min: CONTROL_PROTOCOL_MIN_VERSION,
            host_max: config.proto_version,
        });
    }

    if plugin_abi_version != config.abi_version {
        return Err(HandshakeError::AbiMismatch {
            plugin_abi: plugin_abi_version,
            host_abi: config.abi_version,
        });
    }

    validate_slot_assignment(config.slot_index, config.node_count)?;

    Ok(NegotiatedHandshake {
        proto_version: plugin_proto_version.min(config.proto_version),
        abi_version: config.abi_version,
        slot_index: config.slot_index,
        node_count: config.node_count,
    })
}

/// Validates a plugin-side `HelloAck` message without performing I/O.
///
/// # Errors
///
/// Returns [`HandshakeError`] when `message` is not `HelloAck`, when the
/// negotiated protocol version is outside the plugin-supported range, when the
/// shmem ABI version differs, or when `slot_index >= node_count`.
pub fn plugin_validate_handshake_ack(
    message: HostMsg,
    config: PluginHandshakeConfig,
) -> Result<NegotiatedHandshake, HandshakeError> {
    let HostMsg::HelloAck {
        proto_version,
        abi_version,
        slot_index,
        node_count,
    } = message
    else {
        return Err(HandshakeError::UnexpectedHostMessage { message });
    };

    if proto_version < CONTROL_PROTOCOL_MIN_VERSION || proto_version > config.proto_version {
        return Err(HandshakeError::NegotiatedProtocolOutOfRange {
            negotiated: proto_version,
            plugin_min: CONTROL_PROTOCOL_MIN_VERSION,
            plugin_max: config.proto_version,
        });
    }

    if abi_version != config.abi_version {
        return Err(HandshakeError::AbiMismatch {
            plugin_abi: config.abi_version,
            host_abi: abi_version,
        });
    }

    validate_slot_assignment(slot_index, node_count)?;

    Ok(NegotiatedHandshake {
        proto_version,
        abi_version,
        slot_index,
        node_count,
    })
}

/// Sends a `Setup` frame and its fixed-order descriptors over a Unix socket.
///
/// The descriptors are attached as `SCM_RIGHTS` ancillary data using
/// `sendmsg`, in the RFC-defined order `[shmem_fd, wake_fd]`.
///
/// # Errors
///
/// Returns [`DescriptorHandoverError::Io`] when `sendmsg` fails,
/// [`DescriptorHandoverError::ShortWrite`] if the stream accepts only part of
/// the frame, or [`DescriptorHandoverError::MalformedAncillary`] if the local
/// ancillary buffer cannot represent the fixed descriptor list.
#[cfg(unix)]
pub fn send_setup_with_descriptors(
    socket_fd: RawFd,
    region_len: u64,
    descriptors: SetupDescriptorFds,
) -> Result<(), DescriptorHandoverError> {
    let frame = control_encode_host_msg(&HostMsg::Setup { region_len });
    let fds = [descriptors.shmem_fd, descriptors.wake_fd];
    send_frame_with_fds(socket_fd, &frame, &fds)
}

/// Receives a `Setup` frame and its fixed-order descriptors from a Unix socket.
///
/// The frame must carry exactly two `SCM_RIGHTS` descriptors. The returned
/// descriptors are owned, marked close-on-exec, and returned in the RFC-defined
/// order: shmem first, wake second.
///
/// # Errors
///
/// Returns [`DescriptorHandoverError`] when the socket closes early, the
/// ancillary data is truncated or malformed, the descriptor count is not
/// exactly two, or the frame does not decode to [`HostMsg::Setup`].
#[cfg(unix)]
pub fn recv_setup_with_descriptors(
    socket_fd: RawFd,
) -> Result<ReceivedSetup, DescriptorHandoverError> {
    let mut length_prefix = [0; FRAME_LENGTH_PREFIX_SIZE];
    let raw_fds = recv_setup_prefix_and_fds(socket_fd, &mut length_prefix)?;
    let descriptors = setup_descriptors_from_raw_fds(raw_fds)?;

    let length = u32::from_be_bytes(length_prefix);
    if length > MAX_FRAME_SIZE {
        return Err(DescriptorHandoverError::Decode {
            source: FrameDecodeError::LengthExceedsMax {
                length,
                max: MAX_FRAME_SIZE,
            },
        });
    }

    let payload_len = length as usize;
    let mut frame = Vec::with_capacity(FRAME_LENGTH_PREFIX_SIZE + payload_len);
    frame.extend_from_slice(&length_prefix);
    frame.resize(FRAME_LENGTH_PREFIX_SIZE + payload_len, 0);
    recv_exact_fd(
        socket_fd,
        &mut frame[FRAME_LENGTH_PREFIX_SIZE..],
        "receive setup frame payload",
    )?;

    match control_decode_host_msg(&frame)
        .map_err(|source| DescriptorHandoverError::Decode { source })?
    {
        HostMsg::Setup { region_len } => Ok(ReceivedSetup {
            region_len,
            descriptors,
        }),
        message => Err(DescriptorHandoverError::UnexpectedMessage { message }),
    }
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

#[cfg(unix)]
struct AncillaryBuffer {
    storage: [libc::cmsghdr; ANCILLARY_STORAGE_HEADERS],
    len: usize,
}

#[cfg(unix)]
impl AncillaryBuffer {
    fn for_single_cmsg_fd_capacity(fd_capacity: usize) -> Result<Self, DescriptorHandoverError> {
        let payload_len = fd_capacity
            .checked_mul(std::mem::size_of::<RawFd>())
            .ok_or(DescriptorHandoverError::MalformedAncillary {
                reason: "descriptor payload length overflow",
            })?;
        let len = cmsg_space(payload_len)?;
        Self::with_len(len)
    }

    fn for_split_cmsg_fd_capacity(fd_capacity: usize) -> Result<Self, DescriptorHandoverError> {
        let fd_size = std::mem::size_of::<RawFd>();
        let packed_payload_len = fd_capacity.checked_mul(fd_size).ok_or(
            DescriptorHandoverError::MalformedAncillary {
                reason: "descriptor payload length overflow",
            },
        )?;
        let packed_len = cmsg_space(packed_payload_len)?;
        let split_len = fd_capacity.checked_mul(cmsg_space(fd_size)?).ok_or(
            DescriptorHandoverError::MalformedAncillary {
                reason: "ancillary split-header length overflow",
            },
        )?;

        Self::with_len(packed_len.max(split_len))
    }

    fn with_len(len: usize) -> Result<Self, DescriptorHandoverError> {
        let byte_capacity = ANCILLARY_STORAGE_HEADERS
            .checked_mul(std::mem::size_of::<libc::cmsghdr>())
            .ok_or(DescriptorHandoverError::MalformedAncillary {
                reason: "ancillary storage length overflow",
            })?;
        if len > byte_capacity {
            return Err(DescriptorHandoverError::MalformedAncillary {
                reason: "ancillary storage too small",
            });
        }

        Ok(Self {
            storage: std::array::from_fn(|_| empty_cmsghdr()),
            len,
        })
    }

    fn as_mut_ptr(&mut self) -> *mut libc::c_void {
        self.storage.as_mut_ptr().cast::<libc::c_void>()
    }
}

#[cfg(unix)]
fn empty_cmsghdr() -> libc::cmsghdr {
    libc::cmsghdr {
        cmsg_len: 0,
        cmsg_level: 0,
        cmsg_type: 0,
    }
}

#[cfg(unix)]
fn send_frame_with_fds(
    socket_fd: RawFd,
    frame: &[u8],
    fds: &[RawFd; SETUP_DESCRIPTOR_COUNT],
) -> Result<(), DescriptorHandoverError> {
    let mut iov = libc::iovec {
        iov_base: frame.as_ptr().cast::<libc::c_void>().cast_mut(),
        iov_len: frame.len(),
    };
    let mut control = AncillaryBuffer::for_single_cmsg_fd_capacity(fds.len())?;
    let mut message = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr(),
        msg_controllen: msg_control_len(control.len)?,
        msg_flags: 0,
    };

    // SAFETY: `message` contains a live ancillary buffer and a valid controllen.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if cmsg.is_null() {
        return Err(DescriptorHandoverError::MalformedAncillary {
            reason: "missing first control-message header",
        });
    }

    let payload_len = fds.len() * std::mem::size_of::<RawFd>();
    let cmsg_len = cmsg_len(payload_len)?;
    // SAFETY: `cmsg` points into live aligned `control` storage, and `payload_len` exactly covers `fds`.
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = cmsg_len as _;
        std::ptr::copy_nonoverlapping(
            fds.as_ptr(),
            libc::CMSG_DATA(cmsg).cast::<RawFd>(),
            fds.len(),
        );
    }

    message.msg_controllen = msg_control_len(cmsg_space(payload_len)?)?;
    let sent = loop {
        // SAFETY: `message` references live frame and ancillary buffers for this syscall.
        let result = unsafe { libc::sendmsg(socket_fd, &message, send_flags()) };
        if result < 0 {
            let errno = last_errno_value();
            if errno == libc::EINTR {
                continue;
            }
            return Err(DescriptorHandoverError::Io {
                operation: "send setup frame with descriptors",
                errno,
            });
        }
        break result;
    };

    let actual =
        usize::try_from(sent).map_err(|_| DescriptorHandoverError::MalformedAncillary {
            reason: "negative send length after success",
        })?;
    if actual != frame.len() {
        return Err(DescriptorHandoverError::ShortWrite {
            expected: frame.len(),
            actual,
        });
    }

    Ok(())
}

#[cfg(unix)]
fn recv_setup_prefix_and_fds(
    socket_fd: RawFd,
    length_prefix: &mut [u8; FRAME_LENGTH_PREFIX_SIZE],
) -> Result<Vec<RawFd>, DescriptorHandoverError> {
    let mut iov = libc::iovec {
        iov_base: length_prefix.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: length_prefix.len(),
    };
    let mut control = AncillaryBuffer::for_split_cmsg_fd_capacity(SETUP_DESCRIPTOR_RECV_CAPACITY)?;
    let mut message = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr(),
        msg_controllen: msg_control_len(control.len)?,
        msg_flags: 0,
    };

    let received = loop {
        // SAFETY: `message` references live prefix and ancillary buffers for this syscall.
        let result = unsafe { libc::recvmsg(socket_fd, &mut message, 0) };
        if result < 0 {
            let errno = last_errno_value();
            if errno == libc::EINTR {
                continue;
            }
            return Err(DescriptorHandoverError::Io {
                operation: "receive setup length prefix and descriptors",
                errno,
            });
        }
        break result;
    };

    if received == 0 {
        return Err(DescriptorHandoverError::PeerClosed {
            operation: "receive setup length prefix and descriptors",
        });
    }

    let received =
        usize::try_from(received).map_err(|_| DescriptorHandoverError::MalformedAncillary {
            reason: "negative receive length after success",
        })?;
    let fds = parse_scm_rights_fds(&message)?;
    if received < length_prefix.len()
        && let Err(error) = recv_exact_fd(
            socket_fd,
            &mut length_prefix[received..],
            "receive setup length prefix remainder",
        )
    {
        close_raw_fds(fds);
        return Err(error);
    }

    Ok(fds)
}

#[cfg(unix)]
fn recv_exact_fd(
    socket_fd: RawFd,
    mut buffer: &mut [u8],
    operation: &'static str,
) -> Result<(), DescriptorHandoverError> {
    while !buffer.is_empty() {
        // SAFETY: `buffer` is a live writable byte slice for this syscall.
        let received = unsafe {
            libc::recv(
                socket_fd,
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                buffer.len(),
                0,
            )
        };
        if received < 0 {
            let errno = last_errno_value();
            if errno == libc::EINTR {
                continue;
            }
            return Err(DescriptorHandoverError::Io { operation, errno });
        }
        if received == 0 {
            return Err(DescriptorHandoverError::PeerClosed { operation });
        }

        let received =
            usize::try_from(received).map_err(|_| DescriptorHandoverError::MalformedAncillary {
                reason: "negative receive length after success",
            })?;
        let remaining =
            buffer
                .get_mut(received..)
                .ok_or(DescriptorHandoverError::MalformedAncillary {
                    reason: "receive length exceeded requested buffer",
                })?;
        buffer = remaining;
    }

    Ok(())
}

#[cfg(unix)]
fn parse_scm_rights_fds(message: &libc::msghdr) -> Result<Vec<RawFd>, DescriptorHandoverError> {
    let mut fds = Vec::new();
    let truncated = message.msg_flags & libc::MSG_CTRUNC != 0;
    // SAFETY: `message` contains the live ancillary buffer filled by `recvmsg`.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !cmsg.is_null() {
        // SAFETY: `cmsg` was returned by `CMSG_FIRSTHDR`/`CMSG_NXTHDR` for `message`.
        let header = unsafe { &*cmsg };
        if header.cmsg_level == libc::SOL_SOCKET
            && header.cmsg_type == libc::SCM_RIGHTS
            && let Err(error) = append_rights_fds(header, cmsg, &mut fds)
        {
            close_raw_fds(fds);
            return Err(error);
        }
        // SAFETY: `cmsg` is the current header for `message`.
        cmsg = unsafe { libc::CMSG_NXTHDR(message, cmsg) };
    }

    if truncated {
        close_raw_fds(fds);
        return Err(DescriptorHandoverError::AncillaryTruncated);
    }

    Ok(fds)
}

#[cfg(unix)]
fn append_rights_fds(
    header: &libc::cmsghdr,
    cmsg: *mut libc::cmsghdr,
    fds: &mut Vec<RawFd>,
) -> Result<(), DescriptorHandoverError> {
    let header_len = cmsg_len(0)?;
    let cmsg_len = cmsghdr_len(header)?;
    if cmsg_len < header_len {
        return Err(DescriptorHandoverError::MalformedAncillary {
            reason: "control-message length shorter than header",
        });
    }

    let data_len = cmsg_len - header_len;
    let fd_size = std::mem::size_of::<RawFd>();
    if !data_len.is_multiple_of(fd_size) {
        return Err(DescriptorHandoverError::MalformedAncillary {
            reason: "descriptor payload is not fd-aligned",
        });
    }

    let count = data_len / fd_size;
    // SAFETY: `cmsg` is a valid `SCM_RIGHTS` header for this message.
    let data = unsafe { libc::CMSG_DATA(cmsg).cast::<RawFd>() };
    for index in 0..count {
        // SAFETY: `data_len` is a whole number of `RawFd` elements, and `index` is in bounds.
        let fd = unsafe { *data.add(index) };
        fds.push(fd);
    }

    Ok(())
}

#[cfg(unix)]
fn setup_descriptors_from_raw_fds(
    fds: Vec<RawFd>,
) -> Result<ReceivedSetupDescriptors, DescriptorHandoverError> {
    let [shmem_fd, wake_fd] = match <[RawFd; SETUP_DESCRIPTOR_COUNT]>::try_from(fds) {
        Ok(fds) => fds,
        Err(fds) => {
            let count = fds.len();
            close_raw_fds(fds);
            return Err(DescriptorHandoverError::WrongDescriptorCount { count });
        }
    };

    if let Err(error) = set_cloexec_on_raw_fd(shmem_fd) {
        close_raw_fds(vec![shmem_fd, wake_fd]);
        return Err(error);
    }
    if let Err(error) = set_cloexec_on_raw_fd(wake_fd) {
        close_raw_fds(vec![shmem_fd, wake_fd]);
        return Err(error);
    }

    // SAFETY: the descriptors came from `SCM_RIGHTS` and are uniquely wrapped here.
    let descriptors = unsafe {
        ReceivedSetupDescriptors {
            shmem_fd: OwnedFd::from_raw_fd(shmem_fd),
            wake_fd: OwnedFd::from_raw_fd(wake_fd),
        }
    };
    Ok(descriptors)
}

#[cfg(unix)]
fn close_raw_fds(fds: Vec<RawFd>) {
    for fd in fds {
        // SAFETY: each descriptor came from `SCM_RIGHTS` and is uniquely owned on this error path.
        unsafe {
            drop(OwnedFd::from_raw_fd(fd));
        }
    }
}

#[cfg(unix)]
fn set_cloexec_on_raw_fd(fd: RawFd) -> Result<(), DescriptorHandoverError> {
    // SAFETY: `fcntl(F_GETFD)` reads descriptor flags for a live raw fd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(DescriptorHandoverError::Io {
            operation: "read setup descriptor flags",
            errno: last_errno_value(),
        });
    }

    // SAFETY: `fcntl(F_SETFD)` updates descriptor flags for a live raw fd.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if result < 0 {
        return Err(DescriptorHandoverError::Io {
            operation: "mark setup descriptor close-on-exec",
            errno: last_errno_value(),
        });
    }

    Ok(())
}

#[cfg(unix)]
fn cmsg_space(payload_len: usize) -> Result<usize, DescriptorHandoverError> {
    let payload_len =
        u32::try_from(payload_len).map_err(|_| DescriptorHandoverError::MalformedAncillary {
            reason: "control-message payload length exceeds c_uint",
        })?;
    // SAFETY: `payload_len` is a byte count converted to the libc CMSG width.
    Ok(unsafe { libc::CMSG_SPACE(payload_len) as usize })
}

#[cfg(unix)]
fn cmsg_len(payload_len: usize) -> Result<usize, DescriptorHandoverError> {
    let payload_len =
        u32::try_from(payload_len).map_err(|_| DescriptorHandoverError::MalformedAncillary {
            reason: "control-message payload length exceeds c_uint",
        })?;
    // SAFETY: `payload_len` is a byte count converted to the libc CMSG width.
    Ok(unsafe { libc::CMSG_LEN(payload_len) as usize })
}

#[cfg(all(
    unix,
    any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "watchos"
    )
))]
fn msg_control_len(len: usize) -> Result<MsgControlLen, DescriptorHandoverError> {
    len.try_into()
        .map_err(|_| DescriptorHandoverError::MalformedAncillary {
            reason: "ancillary length exceeds msg_controllen",
        })
}

#[cfg(all(
    unix,
    not(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "watchos"
    ))
))]
fn msg_control_len(len: usize) -> Result<MsgControlLen, DescriptorHandoverError> {
    Ok(len)
}

#[cfg(all(
    unix,
    any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "watchos"
    )
))]
fn cmsghdr_len(header: &libc::cmsghdr) -> Result<usize, DescriptorHandoverError> {
    Ok(header.cmsg_len as usize)
}

#[cfg(all(
    unix,
    not(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "watchos"
    ))
))]
fn cmsghdr_len(header: &libc::cmsghdr) -> Result<usize, DescriptorHandoverError> {
    Ok(header.cmsg_len)
}

#[cfg(all(
    unix,
    any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "watchos"
    )
))]
fn send_flags() -> libc::c_int {
    libc::MSG_NOSIGNAL
}

#[cfg(all(
    unix,
    not(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "watchos"
    ))
))]
fn send_flags() -> libc::c_int {
    0
}

#[cfg(unix)]
fn last_errno_value() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .map_or(0, |errno| errno)
}

fn validate_slot_assignment(slot_index: u32, node_count: u32) -> Result<(), HandshakeError> {
    if slot_index < node_count {
        Ok(())
    } else {
        Err(HandshakeError::InvalidSlot {
            slot_index,
            node_count,
        })
    }
}

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
