//! Exact-width codec for observed-runtime to signed-namespace allocations.
//!
//! ```text
//! AOSNST01 | sandbox:16 | incarnation:16 | observed-generation:8 |
//! observed-audit-digest:32 | target-generation:8 | predecessor:32 | digest:32
//! ```
//!
//! All integers are big endian. The final SHA-256 digest covers a domain
//! separator and every preceding byte.

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

    pub(super) fn decode(mut bytes: &[u8]) -> Result<Self, NamespaceTargetError> {
        if bytes.len() != RECORD_BYTES || take::<8>(&mut bytes)? != *MAGIC {
            return Err(NamespaceTargetError::CorruptState);
        }
        let record = Self {
            identity: (take(&mut bytes)?, take(&mut bytes)?),
            observed_generation: u64::from_be_bytes(take(&mut bytes)?),
            observed_audit_digest: take(&mut bytes)?,
            target_generation: u64::from_be_bytes(take(&mut bytes)?),
            predecessor: take(&mut bytes)?,
            digest: take(&mut bytes)?,
        };
        if !bytes.is_empty()
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
    mut key: &[u8],
    mut bytes: &[u8],
) -> Result<(Identity, Head), NamespaceTargetError> {
    if key.len() != 33 || bytes.len() != 48 || take::<1>(&mut key)? != [b'h'] {
        return Err(NamespaceTargetError::CorruptState);
    }
    let identity = (take(&mut key)?, take(&mut key)?);
    let observed_generation = u64::from_be_bytes(take(&mut bytes)?);
    let target_generation = u64::from_be_bytes(take(&mut bytes)?);
    let digest = take(&mut bytes)?;
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

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], NamespaceTargetError> {
    let (prefix, remaining) = bytes
        .split_at_checked(N)
        .ok_or(NamespaceTargetError::CorruptState)?;
    let value = prefix
        .try_into()
        .map_err(|_| NamespaceTargetError::CorruptState)?;
    *bytes = remaining;
    Ok(value)
}
