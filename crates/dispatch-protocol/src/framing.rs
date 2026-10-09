//! Four-byte big-endian lengths frame canonical Protobuf worker envelopes.
//!
//! ```text
//! [payload_length: u32 big endian][WorkerEnvelope: payload_length bytes]
//! ```
//!
//! Length checks precede allocation. A decoded envelope must re-encode exactly,
//! preventing Protobuf's unknown-field behavior from dropping new semantics.

use std::io::{Read, Write};

use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{wire, ProtocolError};

/// Encodes an envelope as a complete length-prefixed frame.
///
/// # Errors
///
/// Returns an error for an absent operation, unknown enum, or exceeded bound.
pub fn encode_frame(
    envelope: &wire::WorkerEnvelope,
    maximum: u32,
) -> Result<Vec<u8>, ProtocolError> {
    validate_envelope(envelope)?;
    let length = envelope.encoded_len();
    check_length(length, maximum)?;

    let capacity = length.checked_add(4).ok_or(ProtocolError::FrameLength {
        length,
        limit: maximum,
    })?;
    let payload = envelope.encode_to_vec();
    crate::preflight::preflight(&payload)?;
    let mut frame = Vec::with_capacity(capacity);
    frame.extend_from_slice(&(length as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decodes one complete frame and rejects trailing or noncanonical data.
///
/// # Errors
///
/// Returns an error for malformed lengths, unknown fields, or invalid messages.
pub fn decode_frame(bytes: &[u8], maximum: u32) -> Result<wire::WorkerEnvelope, ProtocolError> {
    let prefix: [u8; 4] = bytes
        .get(..4)
        .and_then(|prefix| prefix.try_into().ok())
        .ok_or_else(|| ProtocolError::InvalidMessage("truncated frame prefix".into()))?;
    let length = u32::from_be_bytes(prefix) as usize;
    check_length(length, maximum)?;
    if length.checked_add(4) != Some(bytes.len()) {
        return Err(ProtocolError::InvalidMessage(
            "frame size does not match prefix".into(),
        ));
    }
    decode_payload(&bytes[4..])
}

/// Reads a bounded envelope from a synchronous stream or pipe.
///
/// # Errors
///
/// Returns transport errors for EOF/truncation and protocol errors for bad data.
pub fn read_frame<R: Read>(
    reader: &mut R,
    maximum: u32,
) -> Result<wire::WorkerEnvelope, ProtocolError> {
    let mut prefix = [0; 4];
    reader.read_exact(&mut prefix)?;
    let length = u32::from_be_bytes(prefix) as usize;
    check_length(length, maximum)?;

    let mut payload = vec![0; length];
    reader.read_exact(&mut payload)?;
    decode_payload(&payload)
}

/// Writes and flushes an envelope to a synchronous stream or pipe.
///
/// # Errors
///
/// Returns encoding, bound, or transport failures.
pub fn write_frame<W: Write>(
    writer: &mut W,
    envelope: &wire::WorkerEnvelope,
    maximum: u32,
) -> Result<(), ProtocolError> {
    writer.write_all(&encode_frame(envelope, maximum)?)?;
    writer.flush()?;
    Ok(())
}

/// Reads a bounded envelope from an asynchronous stream or pipe.
///
/// # Errors
///
/// Returns transport errors for EOF/truncation and protocol errors for bad data.
/// Cancellation can consume part of a frame; callers must retire that channel.
pub async fn read_frame_async<R: AsyncRead + Unpin>(
    reader: &mut R,
    maximum: u32,
) -> Result<wire::WorkerEnvelope, ProtocolError> {
    let mut prefix = [0; 4];
    reader.read_exact(&mut prefix).await?;
    let length = u32::from_be_bytes(prefix) as usize;
    check_length(length, maximum)?;

    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).await?;
    decode_payload(&payload)
}

/// Writes and flushes an envelope to an asynchronous stream or pipe.
///
/// # Errors
///
/// Returns encoding, bound, or transport failures.
/// Cancellation can consume part of a frame; callers must retire that channel.
pub async fn write_frame_async<W: AsyncWrite + Unpin>(
    writer: &mut W,
    envelope: &wire::WorkerEnvelope,
    maximum: u32,
) -> Result<(), ProtocolError> {
    writer.write_all(&encode_frame(envelope, maximum)?).await?;
    writer.flush().await?;
    Ok(())
}

fn check_length(length: usize, maximum: u32) -> Result<(), ProtocolError> {
    if length == 0 || length > maximum as usize {
        return Err(ProtocolError::FrameLength {
            length,
            limit: maximum,
        });
    }
    Ok(())
}

fn decode_payload(payload: &[u8]) -> Result<wire::WorkerEnvelope, ProtocolError> {
    crate::preflight::preflight(payload)?;
    let envelope = wire::WorkerEnvelope::decode(payload)?;
    if envelope.encode_to_vec() != payload {
        return Err(ProtocolError::NonCanonicalProtobuf);
    }
    validate_envelope(&envelope)?;
    Ok(envelope)
}

fn validate_envelope(envelope: &wire::WorkerEnvelope) -> Result<(), ProtocolError> {
    use wire::worker_envelope::Body;

    let body = envelope
        .body
        .as_ref()
        .ok_or_else(|| ProtocolError::InvalidMessage("missing envelope operation".into()))?;
    let valid = match body {
        Body::Solve(solve) => solve
            .options
            .as_ref()
            .is_none_or(|options| wire::SearchMode::try_from(options.mode).is_ok()),
        Body::Capabilities(capabilities) => capabilities
            .search_modes
            .iter()
            .all(|mode| wire::SearchMode::try_from(*mode).is_ok()),
        Body::Progress(progress) => wire::ExecutionStage::try_from(progress.stage).is_ok(),
        Body::Finished(finished) => {
            wire::Termination::try_from(finished.termination).is_ok()
                && wire::VerificationClass::try_from(finished.verification_class).is_ok()
                && finished
                    .evidence
                    .as_ref()
                    .is_none_or(|evidence| wire::EvidenceKind::try_from(evidence.kind).is_ok())
                && finished
                    .effective_options
                    .as_ref()
                    .is_none_or(|options| wire::SearchMode::try_from(options.mode).is_ok())
                && finished
                    .timings
                    .iter()
                    .all(|timing| wire::ExecutionStage::try_from(timing.stage).is_ok())
                && finished
                    .error_code
                    .is_none_or(|code| wire::ErrorCode::try_from(code).is_ok())
        }
        Body::Error(error) => wire::ErrorCode::try_from(error.code).is_ok(),
        _ => true,
    };
    if !valid {
        return Err(ProtocolError::InvalidMessage(
            "unknown enum alternative".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::WORKER_VERSION;

    fn hello() -> wire::WorkerEnvelope {
        wire::WorkerEnvelope {
            protocol_version: Some(WORKER_VERSION),
            session_generation: 1,
            worker_generation: 2,
            request_id: 3,
            body: Some(wire::worker_envelope::Body::Hello(wire::Hello::default())),
        }
    }

    #[test]
    fn frame_round_trip_uses_big_endian_length() {
        let envelope = hello();
        let frame = encode_frame(&envelope, 1024).unwrap();
        assert_eq!(&frame[..4], &(envelope.encoded_len() as u32).to_be_bytes());
        assert_eq!(decode_frame(&frame, 1024).unwrap(), envelope);
    }

    #[test]
    fn unknown_fields_and_duplicate_scalars_are_rejected() {
        let mut payload = hello().encode_to_vec();
        payload.extend_from_slice(&[0x20, 0x03]);
        let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&payload);
        assert!(matches!(
            decode_frame(&frame, 1024),
            Err(ProtocolError::NonCanonicalProtobuf)
        ));
    }

    #[test]
    fn oversized_prefix_is_rejected_without_reading_payload() {
        let mut prefix = std::io::Cursor::new(u32::MAX.to_be_bytes());
        assert!(matches!(
            read_frame(&mut prefix, 1024),
            Err(ProtocolError::FrameLength { .. })
        ));
        assert_eq!(prefix.position(), 4);
    }

    #[tokio::test]
    async fn asynchronous_transport_handles_fragmented_frames() {
        let expected = hello();
        let frame = encode_frame(&expected, 1024).unwrap();
        let (mut writer, mut reader) = tokio::io::duplex(1);
        let send = tokio::spawn(async move {
            writer.write_all(&frame).await.unwrap();
        });

        assert_eq!(read_frame_async(&mut reader, 1024).await.unwrap(), expected);
        send.await.unwrap();
    }
}
