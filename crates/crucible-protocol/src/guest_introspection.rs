//! Versioned guest-introspection records carried by shared memory.
//!
//! The protocol carries only owned, fixed-width fields and bounded byte
//! strings. It has no native pointers, file descriptors, callbacks, or
//! process-private layouts. One complete record has this shape:
//!
//! ```text
//! offset  size  field
//! 0       4     magic (`CRGI`)
//! 4       2     protocol version, little-endian
//! 6       1     closed record kind
//! 7       1     flags
//! 8       8     channel identifier, little-endian
//! 16      4     payload length, little-endian
//! 20      N     kind-specific payload
//! ```

use thiserror::Error;

/// Four-byte magic identifying a guest-introspection record.
pub const GUEST_INTROSPECTION_MAGIC: [u8; 4] = *b"CRGI";
/// Current guest-introspection protocol version.
pub const GUEST_INTROSPECTION_PROTOCOL_VERSION: u16 = 1;
/// Fixed record-header length in bytes.
pub const GUEST_INTROSPECTION_HEADER_LEN: usize = 20;
/// Maximum encoded record length admitted by either peer.
pub const GUEST_INTROSPECTION_MAX_RECORD_BYTES: usize = 4592;
/// Maximum data bytes carried by one input or output record.
pub const GUEST_INTROSPECTION_MAX_CHUNK_BYTES: usize = 4096;
/// Maximum argv entries carried by one open request.
pub const GUEST_INTROSPECTION_MAX_ARGV: usize = 128;
/// Maximum UTF-8 bytes carried by one argv entry.
pub const GUEST_INTROSPECTION_MAX_ARG_BYTES: usize = 4096;
/// Reserved channel used only for the agent feature advertisement.
pub const GUEST_INTROSPECTION_FEATURE_CHANNEL_ID: u64 = u64::MAX;
/// Maximum UTF-8 bytes carried by one channel-local failure.
pub const GUEST_INTROSPECTION_MAX_ERROR_BYTES: usize = 1024;

const FLAG_RECORD_TRANSCRIPT: u8 = 1 << 0;
const FLAG_STDERR: u8 = 1 << 1;
const FEATURE_ARGV_EXEC: u32 = 1 << 0;
const FEATURE_PTY: u32 = 1 << 1;
const FEATURE_RESIZE: u32 = 1 << 2;
const FEATURE_SSH_BRIDGE: u32 = 1 << 3;

/// Closed feature advertisement for one guest agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GuestIntrospectionFeatures {
    bits: u32,
    max_channels: u16,
}

impl GuestIntrospectionFeatures {
    /// Builds a feature advertisement from the closed capability set.
    #[must_use]
    pub const fn new(
        argv_exec: bool,
        pty: bool,
        resize: bool,
        ssh_bridge: bool,
        max_channels: u16,
    ) -> Self {
        let mut bits = 0;
        if argv_exec {
            bits |= FEATURE_ARGV_EXEC;
        }
        if pty {
            bits |= FEATURE_PTY;
        }
        if resize {
            bits |= FEATURE_RESIZE;
        }
        if ssh_bridge {
            bits |= FEATURE_SSH_BRIDGE;
        }
        Self { bits, max_channels }
    }

    /// Returns whether argv-based noninteractive exec is supported.
    #[must_use]
    pub const fn argv_exec(self) -> bool {
        self.bits & FEATURE_ARGV_EXEC != 0
    }

    /// Returns whether interactive PTY allocation is supported.
    #[must_use]
    pub const fn pty(self) -> bool {
        self.bits & FEATURE_PTY != 0
    }

    /// Returns whether PTY resize records are supported.
    #[must_use]
    pub const fn resize(self) -> bool {
        self.bits & FEATURE_RESIZE != 0
    }

    /// Returns whether the SSH-compatible byte bridge is supported.
    #[must_use]
    pub const fn ssh_bridge(self) -> bool {
        self.bits & FEATURE_SSH_BRIDGE != 0
    }

    /// Returns the maximum concurrent channel count.
    #[must_use]
    pub const fn max_channels(self) -> u16 {
        self.max_channels
    }
}

/// Origin stream for one guest output chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GuestOutputStream {
    /// Standard output or the combined PTY/SSH stream.
    Stdout,
    /// Standard error for noninteractive argv exec.
    Stderr,
}

/// Stable class of one channel-local guest-agent failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GuestIntrospectionFailureCode {
    /// A child process or PTY could not be opened.
    OpenFailed,
    /// The channel identifier is already active.
    DuplicateChannel,
    /// No active channel has the requested identifier.
    UnknownChannel,
    /// The configured concurrent-channel limit is exhausted.
    ChannelLimit,
    /// Input or terminal control targeted a closed channel.
    ClosedChannel,
    /// A PTY-only operation targeted another channel mode.
    NotPty,
    /// An in-guest process I/O operation failed.
    ProcessIo,
    /// The requested optional feature is unavailable.
    Unsupported,
}

impl GuestIntrospectionFailureCode {
    const fn wire_value(self) -> u16 {
        match self {
            Self::OpenFailed => 1,
            Self::DuplicateChannel => 2,
            Self::UnknownChannel => 3,
            Self::ChannelLimit => 4,
            Self::ClosedChannel => 5,
            Self::NotPty => 6,
            Self::ProcessIo => 7,
            Self::Unsupported => 8,
        }
    }

    const fn from_wire_value(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::OpenFailed),
            2 => Some(Self::DuplicateChannel),
            3 => Some(Self::UnknownChannel),
            4 => Some(Self::ChannelLimit),
            5 => Some(Self::ClosedChannel),
            6 => Some(Self::NotPty),
            7 => Some(Self::ProcessIo),
            8 => Some(Self::Unsupported),
            _ => None,
        }
    }
}

/// One owned guest-introspection protocol message.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum GuestIntrospectionMessage {
    /// Advertises the guest agent's supported protocol features.
    Features(GuestIntrospectionFeatures),
    /// Opens a noninteractive argv-based process.
    Exec {
        /// Program and arguments without shell parsing.
        argv: Vec<String>,
        /// Whether to retain a transcript on the non-canonical branch.
        record_transcript: bool,
    },
    /// Opens an interactive process attached to a guest PTY.
    Pty {
        /// Program and arguments without shell parsing.
        argv: Vec<String>,
        /// Initial terminal columns.
        columns: u16,
        /// Initial terminal rows.
        rows: u16,
        /// Whether to retain a transcript on the non-canonical branch.
        record_transcript: bool,
    },
    /// Opens an SSH-compatible byte bridge terminating at the guest agent.
    Ssh {
        /// Whether to retain a transcript on the non-canonical branch.
        record_transcript: bool,
    },
    /// Carries process or terminal input bytes.
    Input(Vec<u8>),
    /// Resizes an open PTY.
    Resize {
        /// New terminal columns.
        columns: u16,
        /// New terminal rows.
        rows: u16,
    },
    /// Closes process input; repeating it requests channel termination.
    Close,
    /// Carries guest process or terminal output bytes.
    Output {
        /// Logical output stream.
        stream: GuestOutputStream,
        /// Bounded output bytes.
        bytes: Vec<u8>,
    },
    /// Reports final guest process status and closes the channel.
    Exit {
        /// Process exit status, or `-1` when terminated by signal.
        status: i32,
        /// Optional terminating signal number.
        signal: Option<u32>,
    },
    /// Reports a terminal channel-local failure without terminating the agent.
    ///
    /// The channel is closed before publication and its identifier may be
    /// reused after the host receives this record.
    Error {
        /// Stable failure class.
        code: GuestIntrospectionFailureCode,
        /// Bounded human-readable diagnostic from inside the guest.
        message: String,
    },
}

/// One channel-scoped guest-introspection record.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GuestIntrospectionRecord {
    channel_id: u64,
    message: GuestIntrospectionMessage,
}

impl GuestIntrospectionRecord {
    /// Builds a validated record for one channel.
    ///
    /// # Errors
    ///
    /// Returns [`GuestIntrospectionError`] when the channel identifier is zero,
    /// argv or byte chunks exceed their bounds, terminal dimensions are zero,
    /// or an advertisement contains no channel capacity.
    pub fn new(
        channel_id: u64,
        message: GuestIntrospectionMessage,
    ) -> Result<Self, GuestIntrospectionError> {
        if channel_id == 0 {
            return Err(GuestIntrospectionError::ZeroChannelId);
        }
        validate_message(&message)?;
        Ok(Self {
            channel_id,
            message,
        })
    }

    /// Returns the process-local opaque channel identifier.
    #[must_use]
    pub const fn channel_id(&self) -> u64 {
        self.channel_id
    }

    /// Returns the owned message carried by the record.
    #[must_use]
    pub const fn message(&self) -> &GuestIntrospectionMessage {
        &self.message
    }

    /// Validates that this record may travel from the host to the guest agent.
    ///
    /// # Errors
    ///
    /// Returns [`GuestIntrospectionError::WrongDirection`] for a guest response
    /// kind or [`GuestIntrospectionError::FeatureChannelMismatch`] when the
    /// reserved feature channel is used by a request.
    pub fn validate_host_request(&self) -> Result<(), GuestIntrospectionError> {
        if self.channel_id == GUEST_INTROSPECTION_FEATURE_CHANNEL_ID {
            return Err(GuestIntrospectionError::FeatureChannelMismatch);
        }
        match &self.message {
            GuestIntrospectionMessage::Exec { .. }
            | GuestIntrospectionMessage::Pty { .. }
            | GuestIntrospectionMessage::Ssh { .. }
            | GuestIntrospectionMessage::Input(_)
            | GuestIntrospectionMessage::Resize { .. }
            | GuestIntrospectionMessage::Close => Ok(()),
            GuestIntrospectionMessage::Features(_)
            | GuestIntrospectionMessage::Output { .. }
            | GuestIntrospectionMessage::Exit { .. }
            | GuestIntrospectionMessage::Error { .. } => {
                Err(GuestIntrospectionError::WrongDirection)
            }
        }
    }

    /// Validates that this record may travel from the guest agent to the host.
    ///
    /// # Errors
    ///
    /// Returns [`GuestIntrospectionError::WrongDirection`] for a host request
    /// kind or [`GuestIntrospectionError::FeatureChannelMismatch`] when a
    /// feature advertisement uses another channel, or another response uses
    /// the reserved feature channel.
    pub fn validate_guest_response(&self) -> Result<(), GuestIntrospectionError> {
        match &self.message {
            GuestIntrospectionMessage::Features(_)
                if self.channel_id == GUEST_INTROSPECTION_FEATURE_CHANNEL_ID =>
            {
                Ok(())
            }
            GuestIntrospectionMessage::Features(_) => {
                Err(GuestIntrospectionError::FeatureChannelMismatch)
            }
            GuestIntrospectionMessage::Output { .. }
            | GuestIntrospectionMessage::Exit { .. }
            | GuestIntrospectionMessage::Error { .. }
                if self.channel_id != GUEST_INTROSPECTION_FEATURE_CHANNEL_ID =>
            {
                Ok(())
            }
            GuestIntrospectionMessage::Output { .. }
            | GuestIntrospectionMessage::Exit { .. }
            | GuestIntrospectionMessage::Error { .. } => {
                Err(GuestIntrospectionError::FeatureChannelMismatch)
            }
            GuestIntrospectionMessage::Exec { .. }
            | GuestIntrospectionMessage::Pty { .. }
            | GuestIntrospectionMessage::Ssh { .. }
            | GuestIntrospectionMessage::Input(_)
            | GuestIntrospectionMessage::Resize { .. }
            | GuestIntrospectionMessage::Close => Err(GuestIntrospectionError::WrongDirection),
        }
    }

    /// Encodes one complete little-endian protocol record.
    ///
    /// # Errors
    ///
    /// Returns [`GuestIntrospectionError`] if the record is invalid or exceeds
    /// the maximum encoded length.
    pub fn encode(&self) -> Result<Vec<u8>, GuestIntrospectionError> {
        validate_message(&self.message)?;
        let (kind, flags, payload) = encode_message(&self.message)?;
        let total_len = GUEST_INTROSPECTION_HEADER_LEN.saturating_add(payload.len());
        if total_len > GUEST_INTROSPECTION_MAX_RECORD_BYTES {
            return Err(GuestIntrospectionError::RecordTooLarge { len: total_len });
        }
        let payload_len = u32::try_from(payload.len())
            .map_err(|_| GuestIntrospectionError::RecordTooLarge { len: total_len })?;
        let mut output = Vec::with_capacity(total_len);
        output.extend_from_slice(&GUEST_INTROSPECTION_MAGIC);
        output.extend_from_slice(&GUEST_INTROSPECTION_PROTOCOL_VERSION.to_le_bytes());
        output.push(kind);
        output.push(flags);
        output.extend_from_slice(&self.channel_id.to_le_bytes());
        output.extend_from_slice(&payload_len.to_le_bytes());
        output.extend_from_slice(&payload);
        Ok(output)
    }

    /// Decodes and validates one complete protocol record.
    ///
    /// # Errors
    ///
    /// Returns [`GuestIntrospectionError`] for truncated, oversized, malformed,
    /// unsupported, or semantically invalid bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, GuestIntrospectionError> {
        if bytes.len() < GUEST_INTROSPECTION_HEADER_LEN {
            return Err(GuestIntrospectionError::Truncated { len: bytes.len() });
        }
        if bytes.len() > GUEST_INTROSPECTION_MAX_RECORD_BYTES {
            return Err(GuestIntrospectionError::RecordTooLarge { len: bytes.len() });
        }
        if bytes[..4] != GUEST_INTROSPECTION_MAGIC {
            return Err(GuestIntrospectionError::InvalidMagic);
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != GUEST_INTROSPECTION_PROTOCOL_VERSION {
            return Err(GuestIntrospectionError::VersionMismatch {
                expected: GUEST_INTROSPECTION_PROTOCOL_VERSION,
                actual: version,
            });
        }
        let kind = bytes[6];
        let flags = bytes[7];
        let channel_id = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        let payload_len = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]) as usize;
        let expected_len = GUEST_INTROSPECTION_HEADER_LEN.saturating_add(payload_len);
        if bytes.len() != expected_len {
            return Err(GuestIntrospectionError::LengthMismatch {
                expected: expected_len,
                actual: bytes.len(),
            });
        }
        let message = decode_message(kind, flags, &bytes[GUEST_INTROSPECTION_HEADER_LEN..])?;
        Self::new(channel_id, message)
    }
}

const KIND_FEATURES: u8 = 1;
const KIND_EXEC: u8 = 2;
const KIND_PTY: u8 = 3;
const KIND_SSH: u8 = 4;
const KIND_INPUT: u8 = 5;
const KIND_RESIZE: u8 = 6;
const KIND_CLOSE: u8 = 7;
const KIND_OUTPUT: u8 = 8;
const KIND_EXIT: u8 = 9;
const KIND_ERROR: u8 = 10;

fn encode_message(
    message: &GuestIntrospectionMessage,
) -> Result<(u8, u8, Vec<u8>), GuestIntrospectionError> {
    match message {
        GuestIntrospectionMessage::Features(features) => {
            let mut payload = Vec::with_capacity(6);
            payload.extend_from_slice(&features.bits.to_le_bytes());
            payload.extend_from_slice(&features.max_channels.to_le_bytes());
            Ok((KIND_FEATURES, 0, payload))
        }
        GuestIntrospectionMessage::Exec {
            argv,
            record_transcript,
        } => Ok((
            KIND_EXEC,
            transcript_flag(*record_transcript),
            encode_argv(argv)?,
        )),
        GuestIntrospectionMessage::Pty {
            argv,
            columns,
            rows,
            record_transcript,
        } => {
            let mut payload = Vec::new();
            payload.extend_from_slice(&columns.to_le_bytes());
            payload.extend_from_slice(&rows.to_le_bytes());
            payload.extend_from_slice(&encode_argv(argv)?);
            Ok((KIND_PTY, transcript_flag(*record_transcript), payload))
        }
        GuestIntrospectionMessage::Ssh { record_transcript } => {
            Ok((KIND_SSH, transcript_flag(*record_transcript), Vec::new()))
        }
        GuestIntrospectionMessage::Input(bytes) => Ok((KIND_INPUT, 0, bytes.clone())),
        GuestIntrospectionMessage::Resize { columns, rows } => {
            let mut payload = Vec::with_capacity(4);
            payload.extend_from_slice(&columns.to_le_bytes());
            payload.extend_from_slice(&rows.to_le_bytes());
            Ok((KIND_RESIZE, 0, payload))
        }
        GuestIntrospectionMessage::Close => Ok((KIND_CLOSE, 0, Vec::new())),
        GuestIntrospectionMessage::Output { stream, bytes } => Ok((
            KIND_OUTPUT,
            if *stream == GuestOutputStream::Stderr {
                FLAG_STDERR
            } else {
                0
            },
            bytes.clone(),
        )),
        GuestIntrospectionMessage::Exit { status, signal } => {
            let mut payload = Vec::with_capacity(8);
            payload.extend_from_slice(&status.to_le_bytes());
            payload.extend_from_slice(&signal.unwrap_or(0).to_le_bytes());
            Ok((KIND_EXIT, 0, payload))
        }
        GuestIntrospectionMessage::Error { code, message } => {
            let mut payload = Vec::with_capacity(2 + message.len());
            payload.extend_from_slice(&code.wire_value().to_le_bytes());
            payload.extend_from_slice(message.as_bytes());
            Ok((KIND_ERROR, 0, payload))
        }
    }
}

fn decode_message(
    kind: u8,
    flags: u8,
    payload: &[u8],
) -> Result<GuestIntrospectionMessage, GuestIntrospectionError> {
    match kind {
        KIND_FEATURES => {
            require_flags(flags, 0)?;
            require_payload_len(payload, 6)?;
            let bits = read_u32(payload, 0)?;
            let known = FEATURE_ARGV_EXEC | FEATURE_PTY | FEATURE_RESIZE | FEATURE_SSH_BRIDGE;
            if bits & !known != 0 {
                return Err(GuestIntrospectionError::UnknownFeatureBits { bits });
            }
            Ok(GuestIntrospectionMessage::Features(
                GuestIntrospectionFeatures {
                    bits,
                    max_channels: read_u16(payload, 4)?,
                },
            ))
        }
        KIND_EXEC => {
            require_flags(flags, FLAG_RECORD_TRANSCRIPT)?;
            Ok(GuestIntrospectionMessage::Exec {
                argv: decode_argv(payload)?,
                record_transcript: flags & FLAG_RECORD_TRANSCRIPT != 0,
            })
        }
        KIND_PTY => {
            require_flags(flags, FLAG_RECORD_TRANSCRIPT)?;
            if payload.len() < 4 {
                return Err(GuestIntrospectionError::Truncated { len: payload.len() });
            }
            Ok(GuestIntrospectionMessage::Pty {
                columns: read_u16(payload, 0)?,
                rows: read_u16(payload, 2)?,
                argv: decode_argv(&payload[4..])?,
                record_transcript: flags & FLAG_RECORD_TRANSCRIPT != 0,
            })
        }
        KIND_SSH => {
            require_flags(flags, FLAG_RECORD_TRANSCRIPT)?;
            require_payload_len(payload, 0)?;
            Ok(GuestIntrospectionMessage::Ssh {
                record_transcript: flags & FLAG_RECORD_TRANSCRIPT != 0,
            })
        }
        KIND_INPUT => {
            require_flags(flags, 0)?;
            Ok(GuestIntrospectionMessage::Input(payload.to_vec()))
        }
        KIND_RESIZE => {
            require_flags(flags, 0)?;
            require_payload_len(payload, 4)?;
            Ok(GuestIntrospectionMessage::Resize {
                columns: read_u16(payload, 0)?,
                rows: read_u16(payload, 2)?,
            })
        }
        KIND_CLOSE => {
            require_flags(flags, 0)?;
            require_payload_len(payload, 0)?;
            Ok(GuestIntrospectionMessage::Close)
        }
        KIND_OUTPUT => {
            require_flags(flags, FLAG_STDERR)?;
            Ok(GuestIntrospectionMessage::Output {
                stream: if flags & FLAG_STDERR != 0 {
                    GuestOutputStream::Stderr
                } else {
                    GuestOutputStream::Stdout
                },
                bytes: payload.to_vec(),
            })
        }
        KIND_EXIT => {
            require_flags(flags, 0)?;
            require_payload_len(payload, 8)?;
            let signal = read_u32(payload, 4)?;
            Ok(GuestIntrospectionMessage::Exit {
                status: i32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]),
                signal: (signal != 0).then_some(signal),
            })
        }
        KIND_ERROR => {
            require_flags(flags, 0)?;
            let wire_code = read_u16(payload, 0)?;
            let code = GuestIntrospectionFailureCode::from_wire_value(wire_code)
                .ok_or(GuestIntrospectionError::UnknownFailureCode { code: wire_code })?;
            let message = std::str::from_utf8(&payload[2..])
                .map_err(|_| GuestIntrospectionError::InvalidUtf8)?
                .to_owned();
            Ok(GuestIntrospectionMessage::Error { code, message })
        }
        _ => Err(GuestIntrospectionError::UnknownKind { kind }),
    }
}

fn validate_message(message: &GuestIntrospectionMessage) -> Result<(), GuestIntrospectionError> {
    match message {
        GuestIntrospectionMessage::Features(features) if features.max_channels == 0 => {
            Err(GuestIntrospectionError::ZeroChannelCapacity)
        }
        GuestIntrospectionMessage::Features(_) | GuestIntrospectionMessage::Ssh { .. } => Ok(()),
        GuestIntrospectionMessage::Exec { argv, .. } => validate_argv(argv),
        GuestIntrospectionMessage::Pty {
            argv,
            columns,
            rows,
            ..
        } => {
            validate_argv(argv)?;
            if *columns == 0 || *rows == 0 {
                Err(GuestIntrospectionError::InvalidTerminalSize {
                    columns: *columns,
                    rows: *rows,
                })
            } else {
                Ok(())
            }
        }
        GuestIntrospectionMessage::Input(bytes)
        | GuestIntrospectionMessage::Output { bytes, .. } => {
            if bytes.len() > GUEST_INTROSPECTION_MAX_CHUNK_BYTES {
                Err(GuestIntrospectionError::ChunkTooLarge { len: bytes.len() })
            } else {
                Ok(())
            }
        }
        GuestIntrospectionMessage::Resize { columns, rows } if *columns == 0 || *rows == 0 => {
            Err(GuestIntrospectionError::InvalidTerminalSize {
                columns: *columns,
                rows: *rows,
            })
        }
        GuestIntrospectionMessage::Resize { .. }
        | GuestIntrospectionMessage::Close
        | GuestIntrospectionMessage::Exit { .. } => Ok(()),
        GuestIntrospectionMessage::Error { message, .. } => {
            if message.is_empty() || message.len() > GUEST_INTROSPECTION_MAX_ERROR_BYTES {
                Err(GuestIntrospectionError::InvalidErrorLength { len: message.len() })
            } else {
                Ok(())
            }
        }
    }
}

fn validate_argv(argv: &[String]) -> Result<(), GuestIntrospectionError> {
    if argv.is_empty() || argv.len() > GUEST_INTROSPECTION_MAX_ARGV {
        return Err(GuestIntrospectionError::InvalidArgvCount { count: argv.len() });
    }
    for (index, argument) in argv.iter().enumerate() {
        if argument.is_empty() || argument.len() > GUEST_INTROSPECTION_MAX_ARG_BYTES {
            return Err(GuestIntrospectionError::InvalidArgumentLength {
                index,
                len: argument.len(),
            });
        }
    }
    Ok(())
}

fn encode_argv(argv: &[String]) -> Result<Vec<u8>, GuestIntrospectionError> {
    validate_argv(argv)?;
    let count = u16::try_from(argv.len())
        .map_err(|_| GuestIntrospectionError::InvalidArgvCount { count: argv.len() })?;
    let mut output = Vec::new();
    output.extend_from_slice(&count.to_le_bytes());
    for argument in argv {
        let len = u16::try_from(argument.len()).map_err(|_| {
            GuestIntrospectionError::InvalidArgumentLength {
                index: output.len(),
                len: argument.len(),
            }
        })?;
        output.extend_from_slice(&len.to_le_bytes());
        output.extend_from_slice(argument.as_bytes());
    }
    Ok(output)
}

fn decode_argv(payload: &[u8]) -> Result<Vec<String>, GuestIntrospectionError> {
    let count = usize::from(read_u16(payload, 0)?);
    let mut cursor = 2;
    let mut argv = Vec::with_capacity(count);
    for _ in 0..count {
        let len = usize::from(read_u16(payload, cursor)?);
        cursor = cursor.saturating_add(2);
        let end = cursor.saturating_add(len);
        let bytes = payload
            .get(cursor..end)
            .ok_or(GuestIntrospectionError::Truncated { len: payload.len() })?;
        let argument = std::str::from_utf8(bytes)
            .map_err(|_| GuestIntrospectionError::InvalidUtf8)?
            .to_owned();
        argv.push(argument);
        cursor = end;
    }
    if cursor != payload.len() {
        return Err(GuestIntrospectionError::TrailingBytes {
            count: payload.len() - cursor,
        });
    }
    validate_argv(&argv)?;
    Ok(argv)
}

const fn transcript_flag(record: bool) -> u8 {
    if record { FLAG_RECORD_TRANSCRIPT } else { 0 }
}

fn require_flags(actual: u8, allowed: u8) -> Result<(), GuestIntrospectionError> {
    if actual & !allowed == 0 {
        Ok(())
    } else {
        Err(GuestIntrospectionError::UnknownFlags { actual, allowed })
    }
}

fn require_payload_len(payload: &[u8], expected: usize) -> Result<(), GuestIntrospectionError> {
    if payload.len() == expected {
        Ok(())
    } else {
        Err(GuestIntrospectionError::LengthMismatch {
            expected,
            actual: payload.len(),
        })
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, GuestIntrospectionError> {
    let value = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or(GuestIntrospectionError::Truncated { len: bytes.len() })?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, GuestIntrospectionError> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or(GuestIntrospectionError::Truncated { len: bytes.len() })?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

/// Error returned for invalid guest-introspection records.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum GuestIntrospectionError {
    /// A record is shorter than its fixed header or payload fields.
    #[error("guest-introspection record is truncated at {len} bytes")]
    Truncated {
        /// Available byte length.
        len: usize,
    },
    /// A record exceeds the public maximum.
    #[error("guest-introspection record length {len} exceeds the maximum")]
    RecordTooLarge {
        /// Rejected byte length.
        len: usize,
    },
    /// The four-byte record magic does not match.
    #[error("guest-introspection record magic is invalid")]
    InvalidMagic,
    /// The peer uses another protocol version.
    #[error("guest-introspection version mismatch: expected {expected}, actual {actual}")]
    VersionMismatch {
        /// Supported local version.
        expected: u16,
        /// Received peer version.
        actual: u16,
    },
    /// The declared payload length differs from the received bytes.
    #[error("guest-introspection length mismatch: expected {expected}, actual {actual}")]
    LengthMismatch {
        /// Length derived from the record.
        expected: usize,
        /// Received byte length.
        actual: usize,
    },
    /// The record kind is outside the closed vocabulary.
    #[error("guest-introspection record kind {kind} is unknown")]
    UnknownKind {
        /// Rejected wire kind.
        kind: u8,
    },
    /// A record sets flags outside those allowed for its kind.
    #[error("guest-introspection flags {actual:#x} exceed allowed mask {allowed:#x}")]
    UnknownFlags {
        /// Received flag bits.
        actual: u8,
        /// Allowed flag mask for the record kind.
        allowed: u8,
    },
    /// A feature advertisement sets unknown capability bits.
    #[error("guest-introspection feature bits {bits:#x} contain unknown values")]
    UnknownFeatureBits {
        /// Received feature bits.
        bits: u32,
    },
    /// A channel-local failure uses an unknown stable code.
    #[error("guest-introspection failure code {code} is unknown")]
    UnknownFailureCode {
        /// Rejected wire code.
        code: u16,
    },
    /// A record kind is valid but is traveling in the wrong direction.
    #[error("guest-introspection record kind is invalid for this direction")]
    WrongDirection,
    /// The reserved feature channel is used by the wrong record kind.
    #[error("guest-introspection feature channel use is invalid")]
    FeatureChannelMismatch,
    /// Channel zero is reserved and cannot carry requests.
    #[error("guest-introspection channel identifier must be nonzero")]
    ZeroChannelId,
    /// A feature advertisement provides no usable channels.
    #[error("guest-introspection channel capacity must be nonzero")]
    ZeroChannelCapacity,
    /// The argv vector is empty or exceeds its bound.
    #[error("guest-introspection argv count {count} is invalid")]
    InvalidArgvCount {
        /// Rejected entry count.
        count: usize,
    },
    /// One argv entry is empty or exceeds its bound.
    #[error("guest-introspection argv entry {index} has invalid length {len}")]
    InvalidArgumentLength {
        /// Zero-based argv entry index.
        index: usize,
        /// Rejected UTF-8 byte length.
        len: usize,
    },
    /// A byte chunk exceeds its fixed maximum.
    #[error("guest-introspection chunk length {len} exceeds the maximum")]
    ChunkTooLarge {
        /// Rejected chunk length.
        len: usize,
    },
    /// A PTY dimension is zero.
    #[error("guest-introspection terminal size {columns}x{rows} is invalid")]
    InvalidTerminalSize {
        /// Requested terminal columns.
        columns: u16,
        /// Requested terminal rows.
        rows: u16,
    },
    /// A channel-local error diagnostic is empty or exceeds its bound.
    #[error("guest-introspection error message length {len} is invalid")]
    InvalidErrorLength {
        /// Rejected UTF-8 byte length.
        len: usize,
    },
    /// An argv entry is not valid UTF-8.
    #[error("guest-introspection argv contains invalid UTF-8")]
    InvalidUtf8,
    /// Decoding left unconsumed bytes.
    #[error("guest-introspection payload has {count} trailing bytes")]
    TrailingBytes {
        /// Unconsumed byte count.
        count: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_record_kind_round_trips() {
        let records = [
            GuestIntrospectionRecord::new(
                1,
                GuestIntrospectionMessage::Features(GuestIntrospectionFeatures::new(
                    true, true, true, true, 8,
                )),
            ),
            GuestIntrospectionRecord::new(
                2,
                GuestIntrospectionMessage::Exec {
                    argv: vec![String::from("/bin/ls"), String::from("-la")],
                    record_transcript: false,
                },
            ),
            GuestIntrospectionRecord::new(
                3,
                GuestIntrospectionMessage::Pty {
                    argv: vec![String::from("/bin/bash")],
                    columns: 120,
                    rows: 40,
                    record_transcript: true,
                },
            ),
            GuestIntrospectionRecord::new(
                4,
                GuestIntrospectionMessage::Ssh {
                    record_transcript: false,
                },
            ),
            GuestIntrospectionRecord::new(5, GuestIntrospectionMessage::Input(vec![0, 1, 2])),
            GuestIntrospectionRecord::new(
                6,
                GuestIntrospectionMessage::Resize {
                    columns: 80,
                    rows: 24,
                },
            ),
            GuestIntrospectionRecord::new(7, GuestIntrospectionMessage::Close),
            GuestIntrospectionRecord::new(
                8,
                GuestIntrospectionMessage::Output {
                    stream: GuestOutputStream::Stderr,
                    bytes: b"failure\n".to_vec(),
                },
            ),
            GuestIntrospectionRecord::new(
                9,
                GuestIntrospectionMessage::Exit {
                    status: -1,
                    signal: Some(9),
                },
            ),
            GuestIntrospectionRecord::new(
                10,
                GuestIntrospectionMessage::Error {
                    code: GuestIntrospectionFailureCode::OpenFailed,
                    message: String::from("program not found"),
                },
            ),
        ];
        for record in records {
            let record = record.unwrap_or_else(|error| panic!("record should validate: {error}"));
            let bytes = record
                .encode()
                .unwrap_or_else(|error| panic!("record should encode: {error}"));
            assert_eq!(
                GuestIntrospectionRecord::decode(&bytes),
                Ok(record),
                "record bytes should round trip"
            );
        }
    }

    #[test]
    fn malformed_and_unbounded_records_fail_closed() {
        assert_eq!(
            GuestIntrospectionRecord::new(0, GuestIntrospectionMessage::Close),
            Err(GuestIntrospectionError::ZeroChannelId)
        );
        assert_eq!(
            GuestIntrospectionRecord::new(
                1,
                GuestIntrospectionMessage::Input(vec![0; GUEST_INTROSPECTION_MAX_CHUNK_BYTES + 1])
            ),
            Err(GuestIntrospectionError::ChunkTooLarge {
                len: GUEST_INTROSPECTION_MAX_CHUNK_BYTES + 1
            })
        );
        let mut unknown = GuestIntrospectionRecord::new(1, GuestIntrospectionMessage::Close)
            .and_then(|record| record.encode())
            .unwrap_or_else(|error| panic!("fixture should encode: {error}"));
        unknown[6] = u8::MAX;
        assert_eq!(
            GuestIntrospectionRecord::decode(&unknown),
            Err(GuestIntrospectionError::UnknownKind { kind: u8::MAX })
        );
    }

    #[test]
    fn request_and_response_directions_are_closed() {
        let request = GuestIntrospectionRecord::new(1, GuestIntrospectionMessage::Close)
            .unwrap_or_else(|error| panic!("request should validate: {error}"));
        let response = GuestIntrospectionRecord::new(
            1,
            GuestIntrospectionMessage::Output {
                stream: GuestOutputStream::Stdout,
                bytes: vec![1],
            },
        )
        .unwrap_or_else(|error| panic!("response should validate: {error}"));
        let features = GuestIntrospectionRecord::new(
            GUEST_INTROSPECTION_FEATURE_CHANNEL_ID,
            GuestIntrospectionMessage::Features(GuestIntrospectionFeatures::new(
                true, true, true, false, 1,
            )),
        )
        .unwrap_or_else(|error| panic!("features should validate: {error}"));

        assert_eq!(request.validate_host_request(), Ok(()));
        assert_eq!(
            request.validate_guest_response(),
            Err(GuestIntrospectionError::WrongDirection)
        );
        assert_eq!(response.validate_guest_response(), Ok(()));
        assert_eq!(
            response.validate_host_request(),
            Err(GuestIntrospectionError::WrongDirection)
        );
        assert_eq!(features.validate_guest_response(), Ok(()));
        assert_eq!(
            features.validate_host_request(),
            Err(GuestIntrospectionError::FeatureChannelMismatch)
        );
    }
}
