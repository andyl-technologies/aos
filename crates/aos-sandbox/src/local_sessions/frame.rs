//! Bounded local holder-frame parsing and record-subject membership checks.

use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use aos_sandbox_linux::pidfd::PidFdInfo;
use aos_sandbox_linux::seqpacket::ReceivedRecord;

use super::{ActiveSession, LocalSessionError};

const MAGIC: &[u8; 8] = b"AOSLHI01";
const HEADER_BYTES: usize = 10;
const MAXIMUM_HINT_BYTES: usize = 4096;
const MAXIMUM_PAYLOAD_BYTES: usize = 32768;
pub(super) const MAXIMUM_FRAME_BYTES: usize =
    HEADER_BYTES + MAXIMUM_HINT_BYTES + MAXIMUM_PAYLOAD_BYTES;

pub(super) fn validate(
    session: &ActiveSession,
    record: &ReceivedRecord,
) -> Result<(usize, PidFdInfo), LocalSessionError> {
    let (offset, hint) = parse(record.payload())?;
    // The socket's connection establisher may be the controller; the actual
    // holder can receive or delegate its endpoint. Only per-record identity
    // participates in this execution-scope observation.
    let process = record.subject().pidfd();
    session.execution.check_pins()?;
    let anchor = session.execution.anchor();
    let info = match hint {
        None => anchor.verify_exact_membership(process)?,
        Some(hint) => anchor.verify_descendant_membership(process, hint)?,
    };
    session.execution.check_pins()?;
    Ok((offset, info))
}

fn parse(bytes: &[u8]) -> Result<(usize, Option<&Path>), LocalSessionError> {
    if bytes.len() <= HEADER_BYTES || bytes.len() > MAXIMUM_FRAME_BYTES {
        return Err(LocalSessionError::InvalidFrame(
            "frame size is outside bounds",
        ));
    }
    if bytes.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
        return Err(LocalSessionError::InvalidFrame("wrong magic/version"));
    }
    // The minimum length above admits both scalar bytes and the fixed header.
    let hint_length = usize::from(u16::from_be_bytes([bytes[8], bytes[9]]));
    if hint_length > MAXIMUM_HINT_BYTES {
        return Err(LocalSessionError::InvalidFrame("hint exceeds 4096 bytes"));
    }
    let offset = HEADER_BYTES + hint_length;
    let payload = bytes
        .get(offset..)
        .ok_or(LocalSessionError::InvalidFrame("truncated hint"))?;
    if payload.is_empty() || payload.len() > MAXIMUM_PAYLOAD_BYTES {
        return Err(LocalSessionError::InvalidFrame(
            "payload size is outside bounds",
        ));
    }
    let hint = if hint_length == 0 {
        None
    } else {
        Some(Path::new(std::ffi::OsStr::from_bytes(
            &bytes[HEADER_BYTES..offset],
        )))
    };
    Ok((offset, hint))
}

#[cfg(test)]
pub(super) fn encode_test_frame(hint: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_BYTES + hint.len() + payload.len());
    bytes.extend_from_slice(MAGIC);
    let length = u16::try_from(hint.len()).unwrap_or_else(|_| panic!("test hint too large"));
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(hint);
    bytes.extend_from_slice(payload);
    bytes
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "Pure test fixture failures intentionally panic."
)]
mod tests {
    use super::*;

    #[test]
    fn framing_bounds_are_checked_without_kernel_state() {
        let mut malformed = vec![
            b"wrong frame".to_vec(),
            encode_test_frame(b"", b""),
            encode_test_frame(b"", &vec![7; MAXIMUM_PAYLOAD_BYTES + 1]),
            encode_test_frame(&vec![b'x'; MAXIMUM_HINT_BYTES + 1], b"payload"),
            vec![0; MAXIMUM_FRAME_BYTES + 1],
        ];
        let mut truncated = encode_test_frame(b"", b"payload");
        truncated[8..10].copy_from_slice(&4000_u16.to_be_bytes());
        malformed.push(truncated);
        for bytes in malformed {
            assert!(matches!(
                parse(&bytes),
                Err(LocalSessionError::InvalidFrame(_))
            ));
        }

        let bytes = encode_test_frame(
            &vec![b'x'; MAXIMUM_HINT_BYTES],
            &vec![7; MAXIMUM_PAYLOAD_BYTES],
        );
        let (offset, hint) = parse(&bytes).expect("maximum valid frame");
        assert_eq!(offset, HEADER_BYTES + MAXIMUM_HINT_BYTES);
        assert_eq!(
            hint.expect("nonempty hint").as_os_str().as_bytes().len(),
            MAXIMUM_HINT_BYTES
        );
        let bytes = encode_test_frame(b"", b"payload");
        assert_eq!(
            parse(&bytes).expect("exact-scope frame"),
            (HEADER_BYTES, None)
        );
    }
}
