//! Exact-width codec for observed-runtime to signed-namespace allocations.
//!
//! ```text
//! AOSNST01 | sandbox:16 | incarnation:16 | observed-generation:8 |
//! observed-audit-digest:32 | target-generation:8 | predecessor:32 | digest:32
//! ```
//!
//! All integers are big endian. The final SHA-256 digest covers a domain
//! separator and every preceding byte.

use aos_sandbox_model::bounded_codec::BoundedReader;
use sha2::{Digest as _, Sha256};

use super::{Identity, NamespaceTargetError, Record};

const MAGIC: &[u8; 8] = b"AOSNST01";
const DOMAIN: &[u8] = b"aos.sandbox.namespace-target.v1\0";
const RECORD_BYTES: usize = 152;
type Head = (u64, u64, [u8; 32]);

impl Record {
    pub(super) fn key(&self) -> Vec<u8> {
        let mut key = vec![b't'];
        key.extend_from_slice(&self.identity.0);
        key.extend_from_slice(&self.identity.1);
        key.extend_from_slice(&self.observed_generation.to_be_bytes());
        key
    }

    pub(super) fn head(&self) -> Vec<u8> {
        let mut head = self.observed_generation.to_be_bytes().to_vec();
        head.extend_from_slice(&self.target_generation.to_be_bytes());
        head.extend_from_slice(&self.digest);
        head
    }

    fn body(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RECORD_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.identity.0);
        bytes.extend_from_slice(&self.identity.1);
        bytes.extend_from_slice(&self.observed_generation.to_be_bytes());
        bytes.extend_from_slice(&self.observed_audit_digest);
        bytes.extend_from_slice(&self.target_generation.to_be_bytes());
        bytes.extend_from_slice(&self.predecessor);
        bytes
    }

    pub(super) fn compute_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(DOMAIN);
        digest.update(self.body());
        digest.finalize().into()
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let mut bytes = self.body();
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, NamespaceTargetError> {
        let mut reader = BoundedReader::new(bytes, |_| NamespaceTargetError::CorruptState);

        if bytes.len() != RECORD_BYTES || reader.array::<8>()? != *MAGIC {
            return Err(NamespaceTargetError::CorruptState);
        }
        let record = Self {
            identity: (reader.array()?, reader.array()?),
            observed_generation: u64::from_be_bytes(reader.array()?),
            observed_audit_digest: reader.array()?,
            target_generation: u64::from_be_bytes(reader.array()?),
            predecessor: reader.array()?,
            digest: reader.array()?,
        };
        if !reader.is_empty()
            || record.identity.0 == [0; 16]
            || record.identity.1 == [0; 16]
            || record.observed_generation == 0
            || record.observed_audit_digest == [0; 32]
            || record.target_generation == 0
            || record.digest == [0; 32]
            || record.compute_digest() != record.digest
        {
            return Err(NamespaceTargetError::CorruptState);
        }
        Ok(record)
    }
}

pub(super) fn decode_head(
    key: &[u8],
    bytes: &[u8],
) -> Result<(Identity, Head), NamespaceTargetError> {
    let mut key_reader = BoundedReader::new(key, |_| NamespaceTargetError::CorruptState);
    let mut reader = BoundedReader::new(bytes, |_| NamespaceTargetError::CorruptState);

    if key.len() != 33 || bytes.len() != 48 || key_reader.array::<1>()? != [b'h'] {
        return Err(NamespaceTargetError::CorruptState);
    }
    let identity = (key_reader.array()?, key_reader.array()?);
    let observed_generation = u64::from_be_bytes(reader.array()?);
    let target_generation = u64::from_be_bytes(reader.array()?);
    let digest = reader.array()?;
    if identity.0 == [0; 16]
        || identity.1 == [0; 16]
        || observed_generation == 0
        || target_generation == 0
        || digest == [0; 32]
    {
        return Err(NamespaceTargetError::CorruptState);
    }
    Ok((identity, (observed_generation, target_generation, digest)))
}
