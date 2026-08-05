//! Versioned debugger-gateway control and multiplexed byte-stream protocol.
//!
//! The Apache host and GPL debugger gateway exchange only these owned byte
//! frames over a Unix socket. No QEMU structures, callbacks, pointers, or
//! Rust-native enum layouts cross the process boundary.
//!
//! Wire format:
//!
//! ```text
//! offset  size  field
//! 0       8     magic: "CRDBGW1\0"
//! 8       2     protocol version, big-endian
//! 10      1     closed message-kind tag
//! 11      1     flags; zero in version 1
//! 12      4     stream id, big-endian; zero for connection control
//! 16      4     payload length, big-endian
//! 20      N     payload bytes
//! ```

use thiserror::Error;

/// Fixed debugger-gateway frame magic.
pub const DEBUG_GATEWAY_MAGIC: [u8; 8] = *b"CRDBGW1\0";
/// First and current debugger-gateway protocol version.
pub const DEBUG_GATEWAY_PROTOCOL_VERSION: u16 = 1;
/// Fixed debugger-gateway frame header length.
pub const DEBUG_GATEWAY_HEADER_LEN: usize = 20;
/// Maximum payload accepted in a single debugger-gateway frame.
pub const DEBUG_GATEWAY_MAX_PAYLOAD: usize = 1024 * 1024;

/// Stable error codes carried by [`DebugGatewayMessageKind::Error`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum DebugGatewayErrorCode {
    /// Frame, negotiation, or protocol-state violation.
    ProtocolViolation = 1,
    /// The request kind or payload is invalid in the current state.
    InvalidRequest = 2,
    /// A QEMU backend is absent, unavailable, or failed validation.
    BackendUnavailable = 3,
    /// The requested optional feature is not implemented by this build.
    Unsupported = 4,
    /// The gateway encountered an internal failure.
    Internal = 255,
}

impl DebugGatewayErrorCode {
    fn from_tag(tag: u16) -> Result<Self, DebugGatewayErrorPayloadError> {
        match tag {
            1 => Ok(Self::ProtocolViolation),
            2 => Ok(Self::InvalidRequest),
            3 => Ok(Self::BackendUnavailable),
            4 => Ok(Self::Unsupported),
            255 => Ok(Self::Internal),
            _ => Err(DebugGatewayErrorPayloadError::UnknownCode { tag }),
        }
    }
}

/// Typed error body carried by an error frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugGatewayErrorPayload {
    /// Stable machine-readable rejection code.
    pub code: DebugGatewayErrorCode,
    /// Bounded UTF-8 diagnostic for operators and logs.
    pub detail: String,
}

impl DebugGatewayErrorPayload {
    /// Builds and validates a typed gateway error payload.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayErrorPayloadError::DetailTooLarge`] when the UTF-8
    /// detail plus its two-byte code exceeds the frame payload limit.
    pub fn new(
        code: DebugGatewayErrorCode,
        detail: impl Into<String>,
    ) -> Result<Self, DebugGatewayErrorPayloadError> {
        let detail = detail.into();
        if detail.len().saturating_add(2) > DEBUG_GATEWAY_MAX_PAYLOAD {
            return Err(DebugGatewayErrorPayloadError::DetailTooLarge {
                length: detail.len(),
            });
        }
        Ok(Self { code, detail })
    }

    /// Encodes the stable big-endian code followed by UTF-8 detail bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.detail.len() + 2);
        bytes.extend_from_slice(&(self.code as u16).to_be_bytes());
        bytes.extend_from_slice(self.detail.as_bytes());
        bytes
    }

    /// Decodes and validates one typed gateway error payload.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayErrorPayloadError`] for truncation, an unknown
    /// code, invalid UTF-8, or an oversized detail.
    pub fn decode(bytes: &[u8]) -> Result<Self, DebugGatewayErrorPayloadError> {
        if bytes.len() < 2 {
            return Err(DebugGatewayErrorPayloadError::Truncated);
        }
        if bytes.len() > DEBUG_GATEWAY_MAX_PAYLOAD {
            return Err(DebugGatewayErrorPayloadError::DetailTooLarge {
                length: bytes.len().saturating_sub(2),
            });
        }
        let code = DebugGatewayErrorCode::from_tag(u16::from_be_bytes([bytes[0], bytes[1]]))?;
        let detail = std::str::from_utf8(&bytes[2..])
            .map_err(|_| DebugGatewayErrorPayloadError::InvalidUtf8)?
            .to_owned();
        Ok(Self { code, detail })
    }
}

/// Errors produced by typed debugger-gateway error payloads.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DebugGatewayErrorPayloadError {
    /// The payload ended before its two-byte code.
    #[error("debug gateway error payload is truncated")]
    Truncated,
    /// The payload used an unregistered stable error code.
    #[error("unknown debug gateway error code {tag}")]
    UnknownCode {
        /// Rejected numeric code.
        tag: u16,
    },
    /// The diagnostic was not valid UTF-8.
    #[error("debug gateway error detail is not UTF-8")]
    InvalidUtf8,
    /// The diagnostic exceeded the fixed frame payload limit.
    #[error("debug gateway error detail length {length} exceeds the limit")]
    DetailTooLarge {
        /// Rejected detail length.
        length: usize,
    },
}

/// Closed message-kind registry for debugger-gateway version 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum DebugGatewayMessageKind {
    /// Starts protocol negotiation on a new Unix connection.
    Hello = 1,
    /// Confirms the selected protocol version and gateway capabilities.
    HelloAck = 2,
    /// Connects and validates a candidate QEMU RSP endpoint without swapping it.
    BackendPrepare = 3,
    /// Atomically promotes the prepared QEMU RSP endpoint.
    BackendCommit = 4,
    /// Drops a prepared endpoint while retaining the current backend.
    BackendAbort = 5,
    /// Carries GDB Remote Serial Protocol bytes.
    RspData = 6,
    /// Opens a native guest argv-exec stream.
    ExecOpen = 7,
    /// Opens a guest interactive PTY stream.
    PtyOpen = 8,
    /// Opens an SSH-compatible guest byte bridge.
    SshOpen = 9,
    /// Carries bytes for an exec, PTY, or SSH-compatible stream.
    ChannelData = 10,
    /// Half-closes or closes one multiplexed stream.
    ChannelClose = 11,
    /// Acknowledges a control operation or stream open.
    Ack = 12,
    /// Routes an RSP continue/step request to the scheduler-owning host.
    RunControl = 13,
    /// Reports a typed gateway rejection, optionally correlated to a stream.
    Error = 255,
}

impl DebugGatewayMessageKind {
    fn from_tag(tag: u8) -> Result<Self, DebugGatewayDecodeError> {
        match tag {
            1 => Ok(Self::Hello),
            2 => Ok(Self::HelloAck),
            3 => Ok(Self::BackendPrepare),
            4 => Ok(Self::BackendCommit),
            5 => Ok(Self::BackendAbort),
            6 => Ok(Self::RspData),
            7 => Ok(Self::ExecOpen),
            8 => Ok(Self::PtyOpen),
            9 => Ok(Self::SshOpen),
            10 => Ok(Self::ChannelData),
            11 => Ok(Self::ChannelClose),
            12 => Ok(Self::Ack),
            13 => Ok(Self::RunControl),
            255 => Ok(Self::Error),
            _ => Err(DebugGatewayDecodeError::UnknownKind { tag }),
        }
    }

    /// Returns whether this message must name a nonzero multiplexed stream.
    #[must_use]
    pub const fn requires_stream(self) -> bool {
        matches!(
            self,
            Self::RspData
                | Self::ExecOpen
                | Self::PtyOpen
                | Self::SshOpen
                | Self::ChannelData
                | Self::ChannelClose
                | Self::RunControl
        )
    }
}

/// One decoded debugger-gateway frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugGatewayFrame {
    /// Negotiated wire-protocol version.
    pub version: u16,
    /// Closed message kind.
    pub kind: DebugGatewayMessageKind,
    /// Multiplexed stream id, or zero for connection-level control.
    pub stream_id: u32,
    /// Owned kind-specific payload bytes.
    pub payload: Vec<u8>,
}

impl DebugGatewayFrame {
    /// Builds and validates a version-1 debugger-gateway frame.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayEncodeError`] for unsupported versions, oversized
    /// payloads, or invalid stream-id use.
    pub fn v1(
        kind: DebugGatewayMessageKind,
        stream_id: u32,
        payload: impl Into<Vec<u8>>,
    ) -> Result<Self, DebugGatewayEncodeError> {
        let frame = Self {
            version: DEBUG_GATEWAY_PROTOCOL_VERSION,
            kind,
            stream_id,
            payload: payload.into(),
        };
        frame.validate()?;
        Ok(frame)
    }

    /// Encodes this frame into the stable big-endian wire format.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayEncodeError`] when the frame violates version,
    /// payload, or stream-id constraints.
    pub fn encode(&self) -> Result<Vec<u8>, DebugGatewayEncodeError> {
        self.validate()?;
        let payload_len = u32::try_from(self.payload.len()).map_err(|_| {
            DebugGatewayEncodeError::PayloadTooLarge {
                length: self.payload.len(),
            }
        })?;
        let mut bytes = Vec::with_capacity(DEBUG_GATEWAY_HEADER_LEN + self.payload.len());
        bytes.extend_from_slice(&DEBUG_GATEWAY_MAGIC);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.push(self.kind as u8);
        bytes.push(0);
        bytes.extend_from_slice(&self.stream_id.to_be_bytes());
        bytes.extend_from_slice(&payload_len.to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    fn validate(&self) -> Result<(), DebugGatewayEncodeError> {
        if self.version != DEBUG_GATEWAY_PROTOCOL_VERSION {
            return Err(DebugGatewayEncodeError::UnsupportedVersion {
                version: self.version,
            });
        }
        if self.payload.len() > DEBUG_GATEWAY_MAX_PAYLOAD {
            return Err(DebugGatewayEncodeError::PayloadTooLarge {
                length: self.payload.len(),
            });
        }
        if self.kind.requires_stream() && self.stream_id == 0 {
            return Err(DebugGatewayEncodeError::StreamRequired { kind: self.kind });
        }
        if !self.kind.requires_stream()
            && self.kind != DebugGatewayMessageKind::Error
            && self.stream_id != 0
        {
            return Err(DebugGatewayEncodeError::ConnectionControlHasStream {
                kind: self.kind,
                stream_id: self.stream_id,
            });
        }
        Ok(())
    }
}

/// Decodes exactly one complete debugger-gateway frame.
///
/// # Errors
///
/// Returns [`DebugGatewayDecodeError`] when bytes are truncated, malformed,
/// use an unsupported version or kind, exceed the payload limit, or violate
/// stream-id rules.
pub fn decode_debug_gateway_frame(
    bytes: &[u8],
) -> Result<DebugGatewayFrame, DebugGatewayDecodeError> {
    if bytes.len() < DEBUG_GATEWAY_HEADER_LEN {
        return Err(DebugGatewayDecodeError::TruncatedHeader {
            length: bytes.len(),
        });
    }
    if bytes[..8] != DEBUG_GATEWAY_MAGIC {
        return Err(DebugGatewayDecodeError::InvalidMagic);
    }
    let version = u16::from_be_bytes([bytes[8], bytes[9]]);
    if version != DEBUG_GATEWAY_PROTOCOL_VERSION {
        return Err(DebugGatewayDecodeError::UnsupportedVersion { version });
    }
    let kind = DebugGatewayMessageKind::from_tag(bytes[10])?;
    if bytes[11] != 0 {
        return Err(DebugGatewayDecodeError::UnsupportedFlags { flags: bytes[11] });
    }
    let stream_id = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let payload_len_u32 = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let payload_len = usize::try_from(payload_len_u32)
        .map_err(|_| DebugGatewayDecodeError::PayloadTooLarge { length: usize::MAX })?;
    if payload_len > DEBUG_GATEWAY_MAX_PAYLOAD {
        return Err(DebugGatewayDecodeError::PayloadTooLarge {
            length: payload_len,
        });
    }
    let expected = DEBUG_GATEWAY_HEADER_LEN + payload_len;
    if bytes.len() != expected {
        return Err(DebugGatewayDecodeError::FrameLengthMismatch {
            expected,
            actual: bytes.len(),
        });
    }
    let frame = DebugGatewayFrame {
        version,
        kind,
        stream_id,
        payload: bytes[DEBUG_GATEWAY_HEADER_LEN..].to_vec(),
    };
    frame
        .validate()
        .map_err(DebugGatewayDecodeError::InvalidFrame)?;
    Ok(frame)
}

/// Errors produced while encoding a debugger-gateway frame.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DebugGatewayEncodeError {
    /// A frame selected a protocol version this implementation does not encode.
    #[error("unsupported debugger-gateway protocol version {version}")]
    UnsupportedVersion {
        /// Rejected version.
        version: u16,
    },
    /// A payload exceeded the fixed defensive limit.
    #[error("debugger-gateway payload length {length} exceeds the limit")]
    PayloadTooLarge {
        /// Rejected payload length.
        length: usize,
    },
    /// A stream message used the reserved connection-control stream id.
    #[error("debugger-gateway message {kind:?} requires a nonzero stream id")]
    StreamRequired {
        /// Rejected message kind.
        kind: DebugGatewayMessageKind,
    },
    /// A connection-level control message incorrectly named a stream.
    #[error("debugger-gateway control {kind:?} used stream id {stream_id}")]
    ConnectionControlHasStream {
        /// Rejected message kind.
        kind: DebugGatewayMessageKind,
        /// Rejected stream id.
        stream_id: u32,
    },
}

/// Errors produced while decoding a debugger-gateway frame.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DebugGatewayDecodeError {
    /// Input ended before the fixed header was complete.
    #[error("truncated debugger-gateway header of {length} bytes")]
    TruncatedHeader {
        /// Available byte count.
        length: usize,
    },
    /// Input did not begin with [`DEBUG_GATEWAY_MAGIC`].
    #[error("invalid debugger-gateway frame magic")]
    InvalidMagic,
    /// A peer selected an unsupported protocol version.
    #[error("unsupported debugger-gateway protocol version {version}")]
    UnsupportedVersion {
        /// Rejected version.
        version: u16,
    },
    /// A peer sent a tag outside the closed version-1 registry.
    #[error("unknown debugger-gateway message kind {tag}")]
    UnknownKind {
        /// Rejected tag.
        tag: u8,
    },
    /// A peer set flags reserved by version 1.
    #[error("unsupported debugger-gateway flags {flags:#04x}")]
    UnsupportedFlags {
        /// Rejected flag bits.
        flags: u8,
    },
    /// A peer advertised a payload above the defensive limit.
    #[error("debugger-gateway payload length {length} exceeds the limit")]
    PayloadTooLarge {
        /// Rejected payload length.
        length: usize,
    },
    /// The complete input length did not match its payload-length field.
    #[error("debugger-gateway frame length mismatch: expected {expected}, actual {actual}")]
    FrameLengthMismatch {
        /// Length required by the header.
        expected: usize,
        /// Length supplied by the caller.
        actual: usize,
    },
    /// The decoded fields violated a frame invariant.
    #[error("invalid debugger-gateway frame: {0}")]
    InvalidFrame(DebugGatewayEncodeError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_one_golden_rsp_frame_is_stable() {
        let frame = DebugGatewayFrame::v1(DebugGatewayMessageKind::RspData, 7, b"$?#3f".to_vec())
            .unwrap_or_else(|error| panic!("golden frame should build: {error}"));
        let encoded = frame
            .encode()
            .unwrap_or_else(|error| panic!("golden frame should encode: {error}"));
        assert_eq!(
            encoded,
            [
                b'C', b'R', b'D', b'B', b'G', b'W', b'1', 0, 0, 1, 6, 0, 0, 0, 0, 7, 0, 0, 0, 5,
                b'$', b'?', b'#', b'3', b'f',
            ]
        );
        assert_eq!(
            decode_debug_gateway_frame(&encoded)
                .unwrap_or_else(|error| panic!("golden frame should decode: {error}")),
            frame
        );
    }

    #[test]
    fn stream_and_size_invariants_fail_closed() {
        assert!(matches!(
            DebugGatewayFrame::v1(DebugGatewayMessageKind::PtyOpen, 0, Vec::new()),
            Err(DebugGatewayEncodeError::StreamRequired { .. })
        ));
        assert!(matches!(
            DebugGatewayFrame::v1(DebugGatewayMessageKind::Hello, 1, Vec::new()),
            Err(DebugGatewayEncodeError::ConnectionControlHasStream { .. })
        ));
        let oversized = vec![0_u8; DEBUG_GATEWAY_MAX_PAYLOAD + 1];
        assert!(matches!(
            DebugGatewayFrame::v1(DebugGatewayMessageKind::ChannelData, 1, oversized),
            Err(DebugGatewayEncodeError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn typed_error_payload_round_trips_with_stable_code() {
        let payload = DebugGatewayErrorPayload::new(
            DebugGatewayErrorCode::BackendUnavailable,
            "candidate validation failed",
        )
        .unwrap_or_else(|error| panic!("typed error should build: {error}"));
        let encoded = payload.encode();
        assert_eq!(&encoded[..2], &[0, 3]);
        assert_eq!(
            DebugGatewayErrorPayload::decode(&encoded)
                .unwrap_or_else(|error| panic!("typed error should decode: {error}")),
            payload
        );
        assert!(matches!(
            DebugGatewayErrorPayload::decode(&[0, 0]),
            Err(DebugGatewayErrorPayloadError::UnknownCode { tag: 0 })
        ));
    }
}
