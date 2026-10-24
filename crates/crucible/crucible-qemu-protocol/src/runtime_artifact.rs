//! Frames the immutable runtime pair for proposed Setup ten and plan thirteen.
//!
//! ```text
//! CRUCRTA1 | schema1:u32 | bytes192:u32 | process:u64 | account:u64 |
//! Source-assignment[32] | libc-identity[64] | loader-identity[64]
//! identity: role:u32 | machine62:u32 | file-length:u64 | SHA256[32] | zero[16]
//! ```
//!
//! These observations identify files; they authenticate no loaded mapping, issue
//! no retained parent and supply no resource payment or execution permission.
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Exact extent of the separately proposed immutable runtime-pair record.
pub const RUNTIME_ARTIFACT_PAIR_BYTES: usize = 192;

/// Refuses malformed or unsupported immutable runtime-artifact observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid immutable runtime-artifact observation")]
pub struct RuntimeArtifactDecodeError;

/// Identifies one immutable x86-64 ELF artifact without authenticating its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeArtifactIdentity {
    /// Exact positive file extent, representable by the selected signed offset ABI.
    pub file_len: u64,
    /// Nonzero digest of the complete actual artifact, including its ELF headers.
    pub sha256: [u8; 32],
}

impl RuntimeArtifactIdentity {
    fn validate(&self) -> Result<(), RuntimeArtifactDecodeError> {
        if self.file_len == 0 || self.file_len > i64::MAX as u64 || self.sha256 == [0; 32] {
            return Err(RuntimeArtifactDecodeError);
        }
        Ok(())
    }

    fn encode_into(&self, bytes: &mut [u8], role: u32) {
        bytes[..4].copy_from_slice(&role.to_be_bytes());
        bytes[4..8].copy_from_slice(&62_u32.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.file_len.to_be_bytes());
        bytes[16..48].copy_from_slice(&self.sha256);
    }

    fn decode(bytes: &[u8], role: u32) -> Result<Self, RuntimeArtifactDecodeError> {
        if bytes[..4] != role.to_be_bytes()
            || bytes[4..8] != 62_u32.to_be_bytes()
            || bytes[48..].iter().any(|byte| *byte != 0)
        {
            return Err(RuntimeArtifactDecodeError);
        }
        let value = Self {
            file_len: read64(bytes, 8),
            sha256: bytes[16..48]
                .try_into()
                .map_err(|_| RuntimeArtifactDecodeError)?,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Correlates the two immutable files with one containing Source assignment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeArtifactPair {
    /// Actual process incarnation; zero and the exhausted epoch are unsupported.
    pub process_generation: u64,
    /// Actual account generation; zero and the exhausted epoch are unsupported.
    pub account_generation: u64,
    /// Nonzero assignment of the actual containing process resource parent.
    pub source_assignment: [u8; 32],
    /// Exact libc artifact in role one.
    pub libc: RuntimeArtifactIdentity,
    /// Exact matching loader artifact in role two.
    pub loader: RuntimeArtifactIdentity,
}

impl RuntimeArtifactPair {
    fn validate(&self) -> Result<(), RuntimeArtifactDecodeError> {
        if self.process_generation == 0
            || self.process_generation == u64::MAX
            || self.account_generation == 0
            || self.account_generation == u64::MAX
            || self.source_assignment == [0; 32]
        {
            return Err(RuntimeArtifactDecodeError);
        }
        self.libc.validate()?;
        self.loader.validate()?;
        Ok(())
    }

    /// Encodes the exact fixed record without allocating or granting admission.
    ///
    /// # Errors
    /// Refuses unsupported generations, absent assignment/digests and file
    /// lengths that are zero or exceed the selected signed file-offset ABI.
    pub fn encode(&self) -> Result<[u8; RUNTIME_ARTIFACT_PAIR_BYTES], RuntimeArtifactDecodeError> {
        self.validate()?;
        let mut bytes = [0; RUNTIME_ARTIFACT_PAIR_BYTES];
        bytes[..8].copy_from_slice(b"CRUCRTA1");
        bytes[8..12].copy_from_slice(&1_u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&(RUNTIME_ARTIFACT_PAIR_BYTES as u32).to_be_bytes());
        bytes[16..24].copy_from_slice(&self.process_generation.to_be_bytes());
        bytes[24..32].copy_from_slice(&self.account_generation.to_be_bytes());
        bytes[32..64].copy_from_slice(&self.source_assignment);
        self.libc.encode_into(&mut bytes[64..128], 1);
        self.loader.encode_into(&mut bytes[128..192], 2);
        Ok(bytes)
    }

    /// Decodes only the exact supported roles, machine and reserved-byte layout.
    ///
    /// # Errors
    /// Refuses mixed schemas, changed roles/machines, malformed identities,
    /// truncation, trailing bytes and any nonzero reserved byte.
    pub fn decode(bytes: &[u8]) -> Result<Self, RuntimeArtifactDecodeError> {
        if bytes.len() != RUNTIME_ARTIFACT_PAIR_BYTES
            || bytes[..8] != *b"CRUCRTA1"
            || bytes[8..12] != 1_u32.to_be_bytes()
            || bytes[12..16] != (RUNTIME_ARTIFACT_PAIR_BYTES as u32).to_be_bytes()
        {
            return Err(RuntimeArtifactDecodeError);
        }
        let pair = Self {
            process_generation: read64(bytes, 16),
            account_generation: read64(bytes, 24),
            source_assignment: bytes[32..64]
                .try_into()
                .map_err(|_| RuntimeArtifactDecodeError)?,
            libc: RuntimeArtifactIdentity::decode(&bytes[64..128], 1)?,
            loader: RuntimeArtifactIdentity::decode(&bytes[128..192], 2)?,
        };
        pair.validate()?;
        Ok(pair)
    }
}

// All callers first establish the complete fixed containing extent.
fn read64(bytes: &[u8], offset: usize) -> u64 {
    let mut word = [0; 8];
    word.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_be_bytes(word)
}

mod setup;
pub use setup::RuntimeArtifactSetup;
#[cfg(unix)]
pub use setup::send_runtime_artifact_setup_frame_with_descriptors;

#[cfg(test)]
mod tests;
