//! Bounded Host query for one Storage-retained AOSEOR03 output row.
//!
//! The packet is only a readback. It does not attest an accepted Create,
//! physical capture backing, or an all-owner effect barrier.
//!
//! ```text
//! request  = AOSEOQ01 | version:u16be | reserved:u16be | nonce[32]
//!            | deadline:u64be | execution[16] | create[16] | record-digest[32]
//! response = AOSEORQ1 | version:u16be | reserved:u16be | nonce[32]
//!            | request-digest[32] | execution[16] | create[16]
//!            | assignment[32] | claim[32] | record-digest[32]
//!            | admitted:u64be | stdout:u64be | stderr:u64be | sequence:u64be
//! ```

use sha2::{Digest as _, Sha256};

const REQUEST_MAGIC: &[u8; 8] = b"AOSEOQ01";
const RESPONSE_MAGIC: &[u8; 8] = b"AOSEORQ1";
const VERSION: [u8; 2] = 1_u16.to_be_bytes();
const DOMAIN: &[u8] = b"aos.sandbox.storage.existing-output-query.v1\0";

/// Exact maximum size of the query request.
pub const REQUEST_BYTES: usize = 116;
/// Exact maximum size of the query response.
pub const RESPONSE_BYTES: usize = 236;

/// One exact retained-output selector, chosen by Host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExistingOutputRequestV1 {
    /// Nonzero fresh request nonce.
    pub nonce: [u8; 32],
    /// Absolute kernel boottime deadline.
    pub deadline_boottime_nanoseconds: u64,
    /// Execution identity.
    pub execution: [u8; 16],
    /// Accepted Create identity.
    pub create: [u8; 16],
    /// Exact AOSEOR03 digest already known to Host.
    pub record_digest: [u8; 32],
}

/// Storage's current logical row, bound to one exact query or held begin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExistingOutputResponseV1 {
    /// Echoed request nonce.
    pub nonce: [u8; 32],
    /// Domain-separated digest of the canonical query request or held begin.
    pub request_digest: [u8; 32],
    /// Execution identity.
    pub execution: [u8; 16],
    /// Accepted Create identity.
    pub create: [u8; 16],
    /// Retained assignment digest.
    pub assignment_digest: [u8; 32],
    /// Retained v2 claim digest.
    pub claim_digest: [u8; 32],
    /// Retained AOSEOR03 digest.
    pub record_digest: [u8; 32],
    /// Logical admitted bytes.
    pub admitted_bytes: u64,
    /// Maximum stdout capture bytes.
    pub maximum_stdout_bytes: u64,
    /// Maximum stderr capture bytes.
    pub maximum_stderr_bytes: u64,
    /// Storage-local journal head, not an all-owner barrier.
    pub journal_sequence: u64,
}

/// Rejects a noncanonical existing-output packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Storage existing-output packet is invalid")]
pub struct ExistingOutputProtocolErrorV1;

fn take<const N: usize>(
    bytes: &[u8],
    start: usize,
) -> Result<[u8; N], ExistingOutputProtocolErrorV1> {
    bytes
        .get(start..start + N)
        .ok_or(ExistingOutputProtocolErrorV1)?
        .try_into()
        .map_err(|_| ExistingOutputProtocolErrorV1)
}

impl ExistingOutputRequestV1 {
    /// Encodes one canonical query.
    ///
    /// # Errors
    ///
    /// Rejects zero identity, nonce, digest, or deadline fields.
    pub fn encode(self) -> Result<[u8; REQUEST_BYTES], ExistingOutputProtocolErrorV1> {
        if self.nonce == [0; 32]
            || self.deadline_boottime_nanoseconds == 0
            || self.execution == [0; 16]
            || self.create == [0; 16]
            || self.record_digest == [0; 32]
        {
            return Err(ExistingOutputProtocolErrorV1);
        }
        let mut bytes = [0; REQUEST_BYTES];
        bytes[..8].copy_from_slice(REQUEST_MAGIC);
        bytes[8..10].copy_from_slice(&VERSION);
        bytes[12..44].copy_from_slice(&self.nonce);
        bytes[44..52].copy_from_slice(&self.deadline_boottime_nanoseconds.to_be_bytes());
        bytes[52..68].copy_from_slice(&self.execution);
        bytes[68..84].copy_from_slice(&self.create);
        bytes[84..116].copy_from_slice(&self.record_digest);
        Ok(bytes)
    }

    /// Decodes exactly one canonical query.
    ///
    /// # Errors
    ///
    /// Rejects any wrong length, version, reserved bytes, or sentinel field.
    pub fn decode(bytes: &[u8]) -> Result<Self, ExistingOutputProtocolErrorV1> {
        if bytes.len() != REQUEST_BYTES
            || &bytes[..8] != REQUEST_MAGIC
            || bytes[8..10] != VERSION
            || bytes[10..12] != [0; 2]
        {
            return Err(ExistingOutputProtocolErrorV1);
        }
        let request = Self {
            nonce: take(bytes, 12)?,
            deadline_boottime_nanoseconds: u64::from_be_bytes(take(bytes, 44)?),
            execution: take(bytes, 52)?,
            create: take(bytes, 68)?,
            record_digest: take(bytes, 84)?,
        };
        if request.encode()?.as_slice() != bytes {
            return Err(ExistingOutputProtocolErrorV1);
        }
        Ok(request)
    }

    /// Commits to the complete canonical request under a separate domain.
    ///
    /// # Errors
    ///
    /// Rejects an invalid request.
    pub fn digest(self) -> Result<[u8; 32], ExistingOutputProtocolErrorV1> {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        hasher.update(self.encode()?);
        Ok(hasher.finalize().into())
    }
}

impl ExistingOutputResponseV1 {
    /// Encodes the exact retained logical row.
    ///
    /// # Errors
    ///
    /// Rejects zero bindings or an inconsistent byte split.
    pub fn encode(self) -> Result<[u8; RESPONSE_BYTES], ExistingOutputProtocolErrorV1> {
        if self.nonce == [0; 32]
            || self.request_digest == [0; 32]
            || self.execution == [0; 16]
            || self.create == [0; 16]
            || self.assignment_digest == [0; 32]
            || self.claim_digest == [0; 32]
            || self.record_digest == [0; 32]
            || self.journal_sequence == 0
            || self
                .maximum_stdout_bytes
                .checked_add(self.maximum_stderr_bytes)
                != Some(self.admitted_bytes)
        {
            return Err(ExistingOutputProtocolErrorV1);
        }
        let mut bytes = [0; RESPONSE_BYTES];
        bytes[..8].copy_from_slice(RESPONSE_MAGIC);
        bytes[8..10].copy_from_slice(&VERSION);
        bytes[12..44].copy_from_slice(&self.nonce);
        bytes[44..76].copy_from_slice(&self.request_digest);
        bytes[76..92].copy_from_slice(&self.execution);
        bytes[92..108].copy_from_slice(&self.create);
        bytes[108..140].copy_from_slice(&self.assignment_digest);
        bytes[140..172].copy_from_slice(&self.claim_digest);
        bytes[172..204].copy_from_slice(&self.record_digest);
        bytes[204..212].copy_from_slice(&self.admitted_bytes.to_be_bytes());
        bytes[212..220].copy_from_slice(&self.maximum_stdout_bytes.to_be_bytes());
        bytes[220..228].copy_from_slice(&self.maximum_stderr_bytes.to_be_bytes());
        bytes[228..236].copy_from_slice(&self.journal_sequence.to_be_bytes());
        Ok(bytes)
    }

    /// Decodes exactly one canonical reply.
    ///
    /// # Errors
    ///
    /// Rejects any wrong length, version, reserved bytes, or invalid binding.
    pub fn decode(bytes: &[u8]) -> Result<Self, ExistingOutputProtocolErrorV1> {
        if bytes.len() != RESPONSE_BYTES
            || &bytes[..8] != RESPONSE_MAGIC
            || bytes[8..10] != VERSION
            || bytes[10..12] != [0; 2]
        {
            return Err(ExistingOutputProtocolErrorV1);
        }
        let response = Self {
            nonce: take(bytes, 12)?,
            request_digest: take(bytes, 44)?,
            execution: take(bytes, 76)?,
            create: take(bytes, 92)?,
            assignment_digest: take(bytes, 108)?,
            claim_digest: take(bytes, 140)?,
            record_digest: take(bytes, 172)?,
            admitted_bytes: u64::from_be_bytes(take(bytes, 204)?),
            maximum_stdout_bytes: u64::from_be_bytes(take(bytes, 212)?),
            maximum_stderr_bytes: u64::from_be_bytes(take(bytes, 220)?),
            journal_sequence: u64::from_be_bytes(take(bytes, 228)?),
        };
        if response.encode()?.as_slice() != bytes {
            return Err(ExistingOutputProtocolErrorV1);
        }
        Ok(response)
    }

    /// Checks the reply's exact request binding.
    ///
    /// # Errors
    ///
    /// Rejects a stale, swapped, or mismatched response.
    pub fn verify_request(
        &self,
        request: ExistingOutputRequestV1,
    ) -> Result<(), ExistingOutputProtocolErrorV1> {
        if self.nonce != request.nonce
            || self.request_digest != request.digest()?
            || self.execution != request.execution
            || self.create != request.create
            || self.record_digest != request.record_digest
        {
            return Err(ExistingOutputProtocolErrorV1);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_query_rejects_old_names_and_mutated_replies() {
        let request = ExistingOutputRequestV1 {
            nonce: [1; 32],
            deadline_boottime_nanoseconds: 42,
            execution: [2; 16],
            create: [3; 16],
            record_digest: [4; 32],
        };
        let encoded = request.encode().unwrap();
        assert_eq!(ExistingOutputRequestV1::decode(&encoded).unwrap(), request);
        for altered in [0, 8, 10] {
            let mut bytes = encoded;
            bytes[altered] ^= 1;
            assert!(ExistingOutputRequestV1::decode(&bytes).is_err());
        }
        assert!(ExistingOutputRequestV1::decode(&encoded[..115]).is_err());

        let reply = ExistingOutputResponseV1 {
            nonce: request.nonce,
            request_digest: request.digest().unwrap(),
            execution: request.execution,
            create: request.create,
            assignment_digest: [5; 32],
            claim_digest: [6; 32],
            record_digest: request.record_digest,
            admitted_bytes: 0,
            maximum_stdout_bytes: 0,
            maximum_stderr_bytes: 0,
            journal_sequence: 1,
        };
        let bytes = reply.encode().unwrap();
        assert_eq!(ExistingOutputResponseV1::decode(&bytes).unwrap(), reply);
        reply.verify_request(request).unwrap();
        let mut stale = request;
        stale.nonce = [7; 32];
        assert!(reply.verify_request(stale).is_err());
        let mut wrong_record = request;
        wrong_record.record_digest = [8; 32];
        assert!(reply.verify_request(wrong_record).is_err());
        let mut altered = bytes;
        altered[220..228].copy_from_slice(&1_u64.to_be_bytes());
        assert!(ExistingOutputResponseV1::decode(&altered).is_err());
    }
}
