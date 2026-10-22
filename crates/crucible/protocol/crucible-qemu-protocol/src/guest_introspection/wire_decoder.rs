//! Validates borrowed wire records before constructing any owned payload.
//!
//! The wire header and message fields follow the parent module's `CRGI` format.
//! Shared-entry validators retain only borrowed slices; owned decoding uses the
//! same checks and allocates after complete validation succeeds.

use super::*;

/// Retains validated message fields borrowed from one complete wire record.
pub(super) struct BorrowedRecord<'a> {
    pub(super) channel_id: u64,
    pub(super) kind: u8,
    message: BorrowedMessage<'a>,
}

/// Borrows a complete record after framing, UTF-8 and semantic validation.
///
/// # Errors
/// Returns malformed framing, unsupported tags or invalid field errors.
pub(super) fn decode(bytes: &[u8]) -> Result<BorrowedRecord<'_>, GuestIntrospectionError> {
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
    if channel_id == 0 {
        return Err(GuestIntrospectionError::ZeroChannelId);
    }
    message.validate()?;
    Ok(BorrowedRecord {
        channel_id,
        kind,
        message,
    })
}

enum BorrowedMessage<'a> {
    Features(GuestIntrospectionFeatures),
    Exec {
        argv: &'a [u8],
        record_transcript: bool,
    },
    Pty {
        argv: &'a [u8],
        columns: u16,
        rows: u16,
        record_transcript: bool,
    },
    Ssh {
        record_transcript: bool,
    },
    Input(&'a [u8]),
    Resize {
        columns: u16,
        rows: u16,
    },
    Close,
    Output {
        stream: GuestOutputStream,
        bytes: &'a [u8],
    },
    Exit {
        status: i32,
        signal: Option<u32>,
    },
    Error {
        code: GuestIntrospectionFailureCode,
        message: &'a str,
    },
}

impl BorrowedRecord<'_> {
    /// Constructs owned payload fields after complete borrowed validation.
    ///
    /// # Errors
    /// Returns framing or UTF-8 errors if the validated argv invariant is broken.
    pub(super) fn into_owned(self) -> Result<GuestIntrospectionRecord, GuestIntrospectionError> {
        let message = match self.message {
            BorrowedMessage::Features(features) => GuestIntrospectionMessage::Features(features),
            BorrowedMessage::Exec {
                argv,
                record_transcript,
            } => GuestIntrospectionMessage::Exec {
                argv: own_validated_argv(argv)?,
                record_transcript,
            },
            BorrowedMessage::Pty {
                argv,
                columns,
                rows,
                record_transcript,
            } => GuestIntrospectionMessage::Pty {
                argv: own_validated_argv(argv)?,
                columns,
                rows,
                record_transcript,
            },
            BorrowedMessage::Ssh { record_transcript } => {
                GuestIntrospectionMessage::Ssh { record_transcript }
            }
            BorrowedMessage::Input(bytes) => GuestIntrospectionMessage::Input(bytes.to_vec()),
            BorrowedMessage::Resize { columns, rows } => {
                GuestIntrospectionMessage::Resize { columns, rows }
            }
            BorrowedMessage::Close => GuestIntrospectionMessage::Close,
            BorrowedMessage::Output { stream, bytes } => GuestIntrospectionMessage::Output {
                stream,
                bytes: bytes.to_vec(),
            },
            BorrowedMessage::Exit { status, signal } => {
                GuestIntrospectionMessage::Exit { status, signal }
            }
            BorrowedMessage::Error { code, message } => GuestIntrospectionMessage::Error {
                code,
                message: message.to_owned(),
            },
        };
        Ok(GuestIntrospectionRecord {
            channel_id: self.channel_id,
            message,
        })
    }
}

impl BorrowedMessage<'_> {
    fn validate(&self) -> Result<(), GuestIntrospectionError> {
        match self {
            Self::Features(features) if features.max_channels == 0 => {
                Err(GuestIntrospectionError::ZeroChannelCapacity)
            }
            Self::Pty { columns, rows, .. } | Self::Resize { columns, rows }
                if *columns == 0 || *rows == 0 =>
            {
                Err(GuestIntrospectionError::InvalidTerminalSize {
                    columns: *columns,
                    rows: *rows,
                })
            }
            Self::Input(bytes) | Self::Output { bytes, .. }
                if bytes.len() > GUEST_INTROSPECTION_MAX_CHUNK_BYTES =>
            {
                Err(GuestIntrospectionError::ChunkTooLarge { len: bytes.len() })
            }
            Self::Error { message, .. }
                if message.is_empty() || message.len() > GUEST_INTROSPECTION_MAX_ERROR_BYTES =>
            {
                Err(GuestIntrospectionError::InvalidErrorLength { len: message.len() })
            }
            _ => Ok(()),
        }
    }
}

fn decode_message<'a>(
    kind: u8,
    flags: u8,
    payload: &'a [u8],
) -> Result<BorrowedMessage<'a>, GuestIntrospectionError> {
    match kind {
        KIND_FEATURES => {
            require_flags(flags, 0)?;
            require_payload_len(payload, 6)?;
            let bits = read_u32(payload, 0)?;
            let known = FEATURE_ARGV_EXEC | FEATURE_PTY | FEATURE_RESIZE | FEATURE_SSH_BRIDGE;
            if bits & !known != 0 {
                return Err(GuestIntrospectionError::UnknownFeatureBits { bits });
            }
            Ok(BorrowedMessage::Features(GuestIntrospectionFeatures {
                bits,
                max_channels: read_u16(payload, 4)?,
            }))
        }
        KIND_EXEC => {
            require_flags(flags, FLAG_RECORD_TRANSCRIPT)?;
            Ok(BorrowedMessage::Exec {
                argv: validate_argv_bytes(payload)?,
                record_transcript: flags & FLAG_RECORD_TRANSCRIPT != 0,
            })
        }
        KIND_PTY => {
            require_flags(flags, FLAG_RECORD_TRANSCRIPT)?;
            if payload.len() < 4 {
                return Err(GuestIntrospectionError::Truncated { len: payload.len() });
            }
            Ok(BorrowedMessage::Pty {
                columns: read_u16(payload, 0)?,
                rows: read_u16(payload, 2)?,
                argv: validate_argv_bytes(&payload[4..])?,
                record_transcript: flags & FLAG_RECORD_TRANSCRIPT != 0,
            })
        }
        KIND_SSH => {
            require_flags(flags, FLAG_RECORD_TRANSCRIPT)?;
            require_payload_len(payload, 0)?;
            Ok(BorrowedMessage::Ssh {
                record_transcript: flags & FLAG_RECORD_TRANSCRIPT != 0,
            })
        }
        KIND_INPUT => {
            require_flags(flags, 0)?;
            Ok(BorrowedMessage::Input(payload))
        }
        KIND_RESIZE => {
            require_flags(flags, 0)?;
            require_payload_len(payload, 4)?;
            Ok(BorrowedMessage::Resize {
                columns: read_u16(payload, 0)?,
                rows: read_u16(payload, 2)?,
            })
        }
        KIND_CLOSE => {
            require_flags(flags, 0)?;
            require_payload_len(payload, 0)?;
            Ok(BorrowedMessage::Close)
        }
        KIND_OUTPUT => {
            require_flags(flags, FLAG_STDERR)?;
            Ok(BorrowedMessage::Output {
                stream: if flags & FLAG_STDERR != 0 {
                    GuestOutputStream::Stderr
                } else {
                    GuestOutputStream::Stdout
                },
                bytes: payload,
            })
        }
        KIND_EXIT => {
            require_flags(flags, 0)?;
            require_payload_len(payload, 8)?;
            let signal = read_u32(payload, 4)?;
            Ok(BorrowedMessage::Exit {
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
                .map_err(|_| GuestIntrospectionError::InvalidUtf8)?;
            Ok(BorrowedMessage::Error { code, message })
        }
        _ => Err(GuestIntrospectionError::UnknownKind { kind }),
    }
}

fn validate_argv_bytes(payload: &[u8]) -> Result<&[u8], GuestIntrospectionError> {
    let count = usize::from(read_u16(payload, 0)?);
    let mut cursor: usize = 2;
    let mut first_invalid_length = None;
    for index in 0..count {
        let len = usize::from(read_u16(payload, cursor)?);
        cursor = cursor.saturating_add(2);
        let end = cursor.saturating_add(len);
        let bytes = payload
            .get(cursor..end)
            .ok_or(GuestIntrospectionError::Truncated { len: payload.len() })?;
        std::str::from_utf8(bytes).map_err(|_| GuestIntrospectionError::InvalidUtf8)?;
        if first_invalid_length.is_none() && (len == 0 || len > GUEST_INTROSPECTION_MAX_ARG_BYTES) {
            first_invalid_length =
                Some(GuestIntrospectionError::InvalidArgumentLength { index, len });
        }
        cursor = end;
    }
    if cursor != payload.len() {
        return Err(GuestIntrospectionError::TrailingBytes {
            count: payload.len() - cursor,
        });
    }

    // Preserve decode precedence: framing and UTF-8 precede count and lengths.
    // Even a forged count traverses only bytes inside the bounded record, and
    // never sizes an allocation from that untrusted count.
    if count == 0 || count > GUEST_INTROSPECTION_MAX_ARGV {
        return Err(GuestIntrospectionError::InvalidArgvCount { count });
    }
    if let Some(error) = first_invalid_length {
        return Err(error);
    }
    Ok(payload)
}

// Only a fully validated borrowed message reaches this conversion. Its count
// is bounded and all argument framing, UTF-8 and lengths were checked before
// the first allocation; fallible reads keep that invariant explicit.
fn own_validated_argv(payload: &[u8]) -> Result<Vec<String>, GuestIntrospectionError> {
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
    Ok(argv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: u8, channel: u64, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; GUEST_INTROSPECTION_HEADER_LEN];
        bytes[..4].copy_from_slice(b"CRGI");
        bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
        bytes[6] = kind;
        bytes[8..16].copy_from_slice(&channel.to_le_bytes());
        bytes[16..20].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn borrowed_decoder_retains_original_payload_and_argv_storage() {
        let bytes = frame(KIND_INPUT, 7, b"original input");
        let decoded = decode(&bytes).unwrap();
        let BorrowedMessage::Input(payload) = decoded.message else {
            panic!("expected input")
        };
        assert_eq!(payload, b"original input");
        assert_eq!(
            payload.as_ptr(),
            bytes[GUEST_INTROSPECTION_HEADER_LEN..].as_ptr()
        );

        let arguments = [1, 0, 2, 0, b's', b'h'];
        let bytes = frame(KIND_EXEC, 7, &arguments);
        let decoded = decode(&bytes).unwrap();
        let BorrowedMessage::Exec { argv, .. } = decoded.message else {
            panic!("expected argv")
        };
        assert_eq!(argv, arguments);
        assert_eq!(
            argv.as_ptr(),
            bytes[GUEST_INTROSPECTION_HEADER_LEN..].as_ptr()
        );
        assert_eq!(
            GuestIntrospectionRecord::decode(&bytes).unwrap().message(),
            &GuestIntrospectionMessage::Exec {
                argv: vec!["sh".to_owned()],
                record_transcript: false
            }
        );
    }

    #[test]
    fn wire_argv_refusals_preserve_framing_utf8_and_length_precedence() {
        for (payload, expected) in [
            (
                vec![255, 255],
                GuestIntrospectionError::Truncated { len: 2 },
            ),
            (
                vec![0, 0],
                GuestIntrospectionError::InvalidArgvCount { count: 0 },
            ),
            (
                vec![1, 0, 0, 0],
                GuestIntrospectionError::InvalidArgumentLength { index: 0, len: 0 },
            ),
            (
                vec![1, 0, 0, 0, 9],
                GuestIntrospectionError::TrailingBytes { count: 1 },
            ),
            (
                vec![2, 0, 0, 0, 1, 0, 255],
                GuestIntrospectionError::InvalidUtf8,
            ),
        ] {
            let bytes = frame(KIND_EXEC, 7, &payload);

            assert_eq!(
                GuestIntrospectionRecord::validate_encoded(&bytes),
                Err(expected.clone())
            );
            assert_eq!(GuestIntrospectionRecord::decode(&bytes), Err(expected));
        }
    }

    #[test]
    fn wire_validation_preserves_channel_and_payload_semantic_refusals() {
        let payload = vec![0; GUEST_INTROSPECTION_MAX_CHUNK_BYTES + 1];
        let bytes = frame(KIND_INPUT, 0, &payload);
        assert_eq!(
            GuestIntrospectionRecord::validate_encoded(&bytes),
            Err(GuestIntrospectionError::ZeroChannelId)
        );
        let bytes = frame(KIND_INPUT, 7, &payload);
        assert_eq!(
            GuestIntrospectionRecord::validate_encoded(&bytes),
            Err(GuestIntrospectionError::ChunkTooLarge { len: payload.len() })
        );

        let valid = frame(KIND_EXEC, 7, &[1, 0, 2, 0, b's', b'h']);
        assert_eq!(GuestIntrospectionRecord::validate_encoded(&valid), Ok(()));
        for length in 0..valid.len() {
            let expected = if length < GUEST_INTROSPECTION_HEADER_LEN {
                GuestIntrospectionError::Truncated { len: length }
            } else {
                GuestIntrospectionError::LengthMismatch {
                    expected: valid.len(),
                    actual: length,
                }
            };
            assert_eq!(
                GuestIntrospectionRecord::validate_encoded(&valid[..length]),
                Err(expected)
            );
        }
    }
}
