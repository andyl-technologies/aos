//! Streams all registered secondary hashes without retaining object plaintext.

use super::{AttributeName, AttributeValue, Error};
use alloc::format;
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha512};

/// The four registered secondary digests over one complete plaintext object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HashValues {
    /// SHA-256 over plaintext alone.
    pub sha256: [u8; 32],
    /// SHA-512 over plaintext alone.
    pub sha512: [u8; 64],
    /// SHA-1 over `blob <length>\0` followed by plaintext.
    pub git_blob_sha1: [u8; 20],
    /// SHA-256 over `blob <length>\0` followed by plaintext.
    pub git_blob_sha256: [u8; 32],
}

impl HashValues {
    /// Returns the selected registered hash value.
    ///
    /// # Errors
    /// Returns [`Error::UnknownAttribute`] for a classification name.
    pub fn attribute(&self, name: AttributeName) -> Result<AttributeValue, Error> {
        match name {
            AttributeName::Sha256 => Ok(AttributeValue::Sha256(self.sha256)),
            AttributeName::Sha512 => Ok(AttributeValue::Sha512(self.sha512)),
            AttributeName::GitBlobSha1 => Ok(AttributeValue::GitBlobSha1(self.git_blob_sha1)),
            AttributeName::GitBlobSha256 => Ok(AttributeValue::GitBlobSha256(self.git_blob_sha256)),
            _ => Err(Error::UnknownAttribute),
        }
    }
}

/// Stateful full-plaintext producers with a checked declared object length.
pub struct PlaintextHashes {
    declared: u64,
    consumed: u64,
    sha256: Sha256,
    sha512: Sha512,
    git_sha1: Sha1,
    git_sha256: Sha256,
}

impl PlaintextHashes {
    /// Initializes all four producers with the exact decimal Git blob header.
    pub fn new(length: u64) -> Self {
        let header = format!("blob {length}\0");
        let mut git_sha1 = Sha1::new();
        let mut git_sha256 = Sha256::new();
        git_sha1.update(header.as_bytes());
        git_sha256.update(header.as_bytes());
        Self {
            declared: length,
            consumed: 0,
            sha256: Sha256::new(),
            sha512: Sha512::new(),
            git_sha1,
            git_sha256,
        }
    }

    /// Consumes the next plaintext segment in manifest order.
    ///
    /// # Errors
    /// Returns [`Error::LengthMismatch`] before changing state if the declared
    /// total would be exceeded or the byte count overflows.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let consumed = self
            .consumed
            .checked_add(bytes.len() as u64)
            .filter(|&n| n <= self.declared)
            .ok_or(Error::LengthMismatch)?;
        self.sha256.update(bytes);
        self.sha512.update(bytes);
        self.git_sha1.update(bytes);
        self.git_sha256.update(bytes);
        self.consumed = consumed;
        Ok(())
    }

    /// Finalizes only after the declared complete plaintext has been consumed.
    ///
    /// # Errors
    /// Returns [`Error::LengthMismatch`] for an incomplete stream.
    pub fn finish(self) -> Result<HashValues, Error> {
        if self.consumed != self.declared {
            return Err(Error::LengthMismatch);
        }
        Ok(HashValues {
            sha256: self.sha256.finalize().into(),
            sha512: self.sha512.finalize().into(),
            git_blob_sha1: self.git_sha1.finalize().into(),
            git_blob_sha256: self.git_sha256.finalize().into(),
        })
    }
}
