//! Canonical namespace-9 record encodings and key framing.
//!
//! ```text
//! execution/<instance:16> -> "AOSPEX01" || canonical fixed-field JSON draft
//! challenge/<instance:16><nonce:32> -> "AOSPCH01" || boot:16 || clock:16
//!     || wall:i64be || boottime:u64be || expiry:i64be || request_len:u32be
//!     || exact canonical PublisherAdmissionRequestV1 CBOR
//! ```
//!
//! Execution JSON is bounded before serialization; challenge request CBOR is
//! bounded by the portable decoder's hard 32-KiB ceiling. Unknown JSON fields,
//! versions, trailing bytes and alternate encodings are rejected on replay.

use super::{
    CHALLENGE_PREFIX, EXECUTION_PREFIX, PublisherChallengeDraftV1,
    PublisherChallengeRegistrationV1, PublisherExecutionDraftV1, PublisherExecutionRegistrationV1,
    PublisherIngressError,
};
use aos_sandbox_core::format::{
    decode_publisher_admission_request_v1, encode_publisher_admission_request_v1,
};
use aos_sandbox_core::{DecodeLimits, PublisherChallengeV1, PublisherInstanceId};
use std::io::{self, Write};

const EXECUTION_MAGIC: &[u8; 8] = b"AOSPEX01";
const CHALLENGE_MAGIC: &[u8; 8] = b"AOSPCH01";
const HEADER_BYTES: usize = 68;

pub(super) enum Key {
    Execution([u8; 16]),
    Challenge([u8; 16], [u8; 32]),
}

pub(super) fn parse_key(key: &[u8]) -> Result<Key, PublisherIngressError> {
    if let Some(tail) = key.strip_prefix(EXECUTION_PREFIX) {
        let id: [u8; 16] = tail
            .try_into()
            .map_err(|_| PublisherIngressError::MalformedRecord)?;
        if id == [0; 16] {
            return Err(PublisherIngressError::MalformedRecord);
        }
        return Ok(Key::Execution(id));
    }
    if let Some(tail) = key.strip_prefix(CHALLENGE_PREFIX) {
        if tail.len() != 48 {
            return Err(PublisherIngressError::MalformedRecord);
        }
        let id = exact(&tail[..16])?;
        let challenge = exact(&tail[16..])?;
        if id == [0; 16] || challenge == [0; 32] {
            return Err(PublisherIngressError::MalformedRecord);
        }
        return Ok(Key::Challenge(id, challenge));
    }
    Err(PublisherIngressError::MalformedRecord)
}

pub(super) fn execution_key(id: PublisherInstanceId) -> Result<Vec<u8>, PublisherIngressError> {
    if id.as_bytes() == &[0; 16] {
        return Err(PublisherIngressError::InvalidFacts);
    }
    Ok([EXECUTION_PREFIX, id.as_bytes()].concat())
}

pub(super) fn challenge_key(
    id: PublisherInstanceId,
    challenge: PublisherChallengeV1,
) -> Result<Vec<u8>, PublisherIngressError> {
    if id.as_bytes() == &[0; 16] {
        return Err(PublisherIngressError::InvalidFacts);
    }
    Ok([CHALLENGE_PREFIX, id.as_bytes(), challenge.as_bytes()].concat())
}

pub(super) fn encode_execution(
    value: &PublisherExecutionRegistrationV1,
    maximum: usize,
) -> Result<Vec<u8>, PublisherIngressError> {
    let mut buffer = BoundedBuffer {
        bytes: Vec::new(),
        maximum,
    };
    buffer
        .write_all(EXECUTION_MAGIC)
        .map_err(|_| PublisherIngressError::LimitExceeded("record bytes"))?;
    serde_json::to_writer(&mut buffer, value.fields())
        .map_err(|_| PublisherIngressError::LimitExceeded("record bytes"))?;
    Ok(buffer.bytes)
}

pub(super) fn decode_execution(
    bytes: &[u8],
    maximum: usize,
) -> Result<PublisherExecutionRegistrationV1, PublisherIngressError> {
    if bytes.len() > maximum {
        return Err(PublisherIngressError::LimitExceeded("record bytes"));
    }
    let payload = bytes
        .strip_prefix(EXECUTION_MAGIC)
        .ok_or(PublisherIngressError::MalformedRecord)?;
    let draft: PublisherExecutionDraftV1 =
        serde_json::from_slice(payload).map_err(|_| PublisherIngressError::MalformedRecord)?;
    let value = PublisherExecutionRegistrationV1::new(draft)?;
    if encode_execution(&value, maximum)? != bytes {
        return Err(PublisherIngressError::MalformedRecord);
    }
    Ok(value)
}

pub(super) fn encode_challenge(
    value: &PublisherChallengeRegistrationV1,
    maximum: usize,
) -> Result<Vec<u8>, PublisherIngressError> {
    let fields = value.fields();
    let request = encode_publisher_admission_request_v1(&fields.request);
    let size = HEADER_BYTES
        .checked_add(request.len())
        .ok_or(PublisherIngressError::LimitExceeded("record bytes"))?;
    if size > maximum {
        return Err(PublisherIngressError::LimitExceeded("record bytes"));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| PublisherIngressError::LimitExceeded("allocation"))?;
    bytes.extend_from_slice(CHALLENGE_MAGIC);
    bytes.extend_from_slice(&fields.boot_id);
    bytes.extend_from_slice(&fields.clock_provenance);
    bytes.extend_from_slice(&fields.registered_wall_seconds.to_be_bytes());
    bytes.extend_from_slice(&fields.registered_boottime_nanoseconds.to_be_bytes());
    bytes.extend_from_slice(&fields.expires_wall_seconds.to_be_bytes());
    let length = u32::try_from(request.len())
        .map_err(|_| PublisherIngressError::LimitExceeded("request bytes"))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(&request);
    Ok(bytes)
}

pub(super) fn decode_challenge(
    bytes: &[u8],
    maximum: usize,
) -> Result<PublisherChallengeRegistrationV1, PublisherIngressError> {
    if bytes.len() > maximum {
        return Err(PublisherIngressError::LimitExceeded("record bytes"));
    }
    if bytes.len() < HEADER_BYTES || !bytes.starts_with(CHALLENGE_MAGIC) {
        return Err(PublisherIngressError::MalformedRecord);
    }
    let length = u32::from_be_bytes(exact(&bytes[64..68])?) as usize;
    if length != bytes.len() - HEADER_BYTES {
        return Err(PublisherIngressError::MalformedRecord);
    }
    let request = decode_publisher_admission_request_v1(
        &bytes[HEADER_BYTES..],
        DecodeLimits {
            maximum_bytes: 32768,
            maximum_collection_items: 64,
            maximum_total_items: 1024,
            maximum_byte_string_bytes: 256,
            maximum_text_bytes: 255,
            maximum_depth: 16,
        },
    )
    .map_err(|_| PublisherIngressError::MalformedRecord)?;
    let value = PublisherChallengeRegistrationV1::new(PublisherChallengeDraftV1 {
        request,
        boot_id: exact(&bytes[8..24])?,
        clock_provenance: exact(&bytes[24..40])?,
        registered_wall_seconds: i64::from_be_bytes(exact(&bytes[40..48])?),
        registered_boottime_nanoseconds: u64::from_be_bytes(exact(&bytes[48..56])?),
        expires_wall_seconds: i64::from_be_bytes(exact(&bytes[56..64])?),
    })?;
    if encode_challenge(&value, maximum)? != bytes {
        return Err(PublisherIngressError::MalformedRecord);
    }
    Ok(value)
}

fn exact<const N: usize>(bytes: &[u8]) -> Result<[u8; N], PublisherIngressError> {
    bytes
        .try_into()
        .map_err(|_| PublisherIngressError::MalformedRecord)
}

struct BoundedBuffer {
    bytes: Vec<u8>,
    maximum: usize,
}
impl Write for BoundedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("record limit"))?;
        if next > self.maximum {
            return Err(io::Error::other("record limit"));
        }
        if next > self.bytes.capacity() {
            let capacity = next
                .max(self.bytes.capacity().saturating_mul(2))
                .min(self.maximum);
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(io::Error::other)?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
