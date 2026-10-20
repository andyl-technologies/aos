//! Hashes actual payload bytes with explicit domain and length framing.
//!
//! Bank hashes exactly match Format's CNP/1 `cnp.blob.v1` ContentRef hash.
//! Diagnostic hashes use the same framing under a separate private domain.

use super::WireError;

const BANK_DOMAIN: &[u8] = b"cnp.blob.v1";
const DIAGNOSTIC_DOMAIN: &[u8] = b"crucible.source-birth.diagnostic/1";

/// Incrementally commits exactly one declared payload without storing its bytes.
pub struct PayloadHasher {
    hasher: blake3::Hasher,
    length: u64,
    consumed: u64,
}

impl PayloadHasher {
    /// Starts the existing CNP blob identity for one actual bank length.
    pub fn bank(length: u64) -> Self {
        Self::new(BANK_DOMAIN, length)
    }

    /// Starts a domain-separated diagnostic identity for its complete byte length.
    pub fn diagnostic(length: u64) -> Self {
        Self::new(DIAGNOSTIC_DOMAIN, length)
    }

    fn new(domain: &[u8], length: u64) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"CNP/1\0");
        // Both private constant domains have a fixed u32-representable length.
        hasher.update(&(domain.len() as u32).to_be_bytes());
        hasher.update(domain);
        hasher.update(&length.to_be_bytes());
        Self {
            hasher,
            length,
            consumed: 0,
        }
    }

    /// Adds actual bytes without exceeding the declared payload length.
    ///
    /// # Errors
    /// Refuses unrepresentable or excess input before changing the digest state.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), WireError> {
        let count = u64::try_from(bytes.len()).map_err(|_| WireError::LengthOverflow)?;
        let consumed = self
            .consumed
            .checked_add(count)
            .ok_or(WireError::HashLength)?;
        if consumed > self.length {
            return Err(WireError::HashLength);
        }
        self.hasher.update(bytes);
        self.consumed = consumed;
        Ok(())
    }

    /// Returns a raw digest only after exactly the declared bytes were consumed.
    ///
    /// # Errors
    /// Refuses a short payload rather than hashing it under a false length.
    pub fn finish(self) -> Result<[u8; 32], WireError> {
        if self.consumed != self.length {
            return Err(WireError::HashLength);
        }
        Ok(*self.hasher.finalize().as_bytes())
    }
}

pub(super) fn bank_digest(bytes: &[u8]) -> Result<[u8; 32], WireError> {
    let mut hasher = PayloadHasher::bank(super::length(bytes)?);
    hasher.update(bytes)?;
    hasher.finish()
}

pub(super) fn diagnostic_digest(bytes: &[u8]) -> Result<[u8; 32], WireError> {
    let mut hasher = PayloadHasher::diagnostic(super::length(bytes)?);
    hasher.update(bytes)?;
    hasher.finish()
}
