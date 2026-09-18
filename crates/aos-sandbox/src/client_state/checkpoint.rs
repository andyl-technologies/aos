//! Canonical bounded watch-resume checkpoints with binding provenance.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::watch::WatchResumePointV1;
use crate::controller_query::event::{BoundWatchCursorV1, InvalidWatchEvent};
use crate::controller_query::model::QueryBindingV1;

const CHECKPOINT_MAGIC: &[u8; 8] = b"AOSWCP01";
const CHECKPOINT_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.watch-checkpoint.v1\0";
/// Maximum canonical checkpoint bytes.
pub const MAXIMUM_WATCH_CHECKPOINT_BYTES: usize = 8 * 1024;

/// Reports malformed, noncanonical, or substituted checkpoint state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidWatchCheckpoint {
    /// The byte layout, version, size, or cursor is invalid.
    #[error("watch checkpoint encoding is invalid")]
    InvalidEncoding,
    /// Embedded query or authorization commitments do not match the caller.
    #[error("watch checkpoint binding was substituted")]
    BindingMismatch,
}

impl From<InvalidWatchEvent> for InvalidWatchCheckpoint {
    fn from(_: InvalidWatchEvent) -> Self {
        Self::InvalidEncoding
    }
}

/// Stores canonical bytes and their domain-separated digest.
#[derive(Clone, Eq, PartialEq)]
pub struct WatchCheckpointV1 {
    bytes: Vec<u8>,
    digest: ObjectDigest,
}

impl std::fmt::Debug for WatchCheckpointV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WatchCheckpointV1")
            .field("redacted_bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl WatchCheckpointV1 {
    /// Encodes one fully applied query-bound resume point canonically.
    #[must_use]
    pub fn encode(resume: &WatchResumePointV1) -> Self {
        let mut bytes = Vec::with_capacity(8 + 7 * 32 + 8 + 2 + resume.cursor().as_bytes().len());
        bytes.extend_from_slice(CHECKPOINT_MAGIC);
        append_binding(&mut bytes, resume.binding());
        bytes.extend_from_slice(&resume.sequence().to_be_bytes());
        // BoundWatchCursorV1 is capped at 4 KiB, below the u16 encoding ceiling.
        let cursor_length = resume.cursor().as_bytes().len() as u16;
        bytes.extend_from_slice(&cursor_length.to_be_bytes());
        bytes.extend_from_slice(resume.cursor().as_bytes());
        Self {
            digest: checkpoint_digest(&bytes),
            bytes,
        }
    }

    /// Decodes canonical bytes under an exact binding and stored digest.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidWatchCheckpoint`] for malformed bytes, a binding
    /// substitution, zero sequence, or noncanonical re-encoding.
    pub fn decode(
        bytes: &[u8],
        expected_binding: QueryBindingV1,
        expected_digest: ObjectDigest,
    ) -> Result<(Self, WatchResumePointV1), InvalidWatchCheckpoint> {
        if bytes.len() < 8 + 7 * 32 + 8 + 2 || bytes.len() > MAXIMUM_WATCH_CHECKPOINT_BYTES {
            return Err(InvalidWatchCheckpoint::InvalidEncoding);
        }
        if expected_digest.as_bytes() == &[0; 32] || checkpoint_digest(bytes) != expected_digest {
            return Err(InvalidWatchCheckpoint::InvalidEncoding);
        }
        let (prefix, remainder) = bytes.split_at(8 + 7 * 32);
        let mut expected_prefix = Vec::with_capacity(prefix.len());
        expected_prefix.extend_from_slice(CHECKPOINT_MAGIC);
        append_binding(&mut expected_prefix, expected_binding);
        if prefix != expected_prefix {
            return Err(InvalidWatchCheckpoint::BindingMismatch);
        }
        let sequence = u64::from_be_bytes(
            remainder[..8]
                .try_into()
                .map_err(|_| InvalidWatchCheckpoint::InvalidEncoding)?,
        );
        let cursor_length = u16::from_be_bytes(
            remainder[8..10]
                .try_into()
                .map_err(|_| InvalidWatchCheckpoint::InvalidEncoding)?,
        ) as usize;
        let cursor_bytes = remainder
            .get(10..)
            .filter(|cursor| cursor.len() == cursor_length)
            .ok_or(InvalidWatchCheckpoint::InvalidEncoding)?;
        if sequence == 0 {
            return Err(InvalidWatchCheckpoint::InvalidEncoding);
        }
        let cursor = BoundWatchCursorV1::from_checkpoint(expected_binding, cursor_bytes.to_vec())?;
        let resume = WatchResumePointV1::from_checkpoint(cursor, sequence);
        let checkpoint = Self::encode(&resume);
        if checkpoint.bytes != bytes {
            return Err(InvalidWatchCheckpoint::InvalidEncoding);
        }
        Ok((checkpoint, resume))
    }

    /// Returns canonical checkpoint bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the domain-separated checkpoint digest.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }
}

fn append_binding(output: &mut Vec<u8>, binding: QueryBindingV1) {
    output.extend_from_slice(binding.query().digest().as_bytes());
    output.extend_from_slice(binding.filters().digest().as_bytes());
    output.extend_from_slice(binding.sort().digest().as_bytes());
    output.extend_from_slice(binding.principal().digest().as_bytes());
    output.extend_from_slice(binding.visibility().digest().as_bytes());
    output.extend_from_slice(binding.authorization().digest().as_bytes());
    output.extend_from_slice(binding.schema().digest().as_bytes());
}

fn checkpoint_digest(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(CHECKPOINT_DIGEST_DOMAIN)
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}
