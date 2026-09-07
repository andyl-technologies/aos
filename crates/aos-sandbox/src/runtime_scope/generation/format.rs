//! Exact-width generation audit codec, independent of live kernel proofs.
//!
//! ```text
//! AOSNSG01 | sandbox:16 | incarnation:16 | generation:8 |
//! runtime:32 | scope:32 | pid:4 | leaf-cgroup:8 | anchor:8 |
//! binding-revision:8 | binding-digest:32 | predecessor:32 | digest:32
//! ```
//!
//! The version is part of the magic. All integers are big endian; the final
//! SHA-256 digest covers a domain separator and every preceding byte.

use sha2::{Digest as _, Sha256};

use super::{Facts, Identity, Record, RuntimeGenerationError};

const MAGIC: &[u8; 8] = b"AOSNSG01";
const DOMAIN: &[u8] = b"aos.sandbox.runtime-generation.v1\0";
const RECORD_BYTES: usize = 236;

impl Record {
    pub(super) fn key(&self) -> Vec<u8> {
        let mut key = vec![b'g'];
        key.extend_from_slice(&self.facts.identity.0);
        key.extend_from_slice(&self.facts.identity.1);
        key.extend_from_slice(&self.generation.to_be_bytes());
        key
    }

    pub(super) fn head(&self) -> Vec<u8> {
        let mut head = self.generation.to_be_bytes().to_vec();
        head.extend_from_slice(&self.digest);
        head
    }

    fn body(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RECORD_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.facts.identity.0);
        bytes.extend_from_slice(&self.facts.identity.1);
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.facts.runtime);
        bytes.extend_from_slice(&self.facts.scope);
        bytes.extend_from_slice(&self.facts.pid.to_be_bytes());
        bytes.extend_from_slice(&self.facts.leaf_cgroup.to_be_bytes());
        bytes.extend_from_slice(&self.facts.anchor.to_be_bytes());
        bytes.extend_from_slice(&self.facts.binding_revision.to_be_bytes());
        bytes.extend_from_slice(&self.facts.binding_digest);
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

    pub(super) fn decode(mut bytes: &[u8]) -> Result<Self, RuntimeGenerationError> {
        if bytes.len() != RECORD_BYTES || take::<8>(&mut bytes)? != *MAGIC {
            return Err(RuntimeGenerationError::CorruptState);
        }
        let identity = (take(&mut bytes)?, take(&mut bytes)?);
        let generation = u64::from_be_bytes(take(&mut bytes)?);
        let facts = Facts {
            identity,
            runtime: take(&mut bytes)?,
            scope: take(&mut bytes)?,
            pid: u32::from_be_bytes(take(&mut bytes)?),
            leaf_cgroup: u64::from_be_bytes(take(&mut bytes)?),
            anchor: u64::from_be_bytes(take(&mut bytes)?),
            binding_revision: u64::from_be_bytes(take(&mut bytes)?),
            binding_digest: take(&mut bytes)?,
        };
        let record = Self {
            facts,
            generation,
            predecessor: take(&mut bytes)?,
            digest: take(&mut bytes)?,
        };
        if !bytes.is_empty()
            || identity.0 == [0; 16]
            || identity.1 == [0; 16]
            || generation == 0
            || record.facts.runtime == [0; 32]
            || record.facts.scope == [0; 32]
            || record.facts.pid == 0
            || record.facts.leaf_cgroup == 0
            || record.facts.anchor == 0
            || record.facts.binding_revision == 0
            || record.facts.binding_digest == [0; 32]
            || record.digest == [0; 32]
            || (generation == 1) != (record.predecessor == [0; 32])
            || record.compute_digest() != record.digest
        {
            return Err(RuntimeGenerationError::CorruptState);
        }
        Ok(record)
    }
}

pub(super) fn decode_head(
    mut key: &[u8],
    mut bytes: &[u8],
) -> Result<(Identity, (u64, [u8; 32])), RuntimeGenerationError> {
    if key.len() != 33 || bytes.len() != 40 || take::<1>(&mut key)? != [b'h'] {
        return Err(RuntimeGenerationError::CorruptState);
    }
    let identity = (take(&mut key)?, take(&mut key)?);
    let generation = u64::from_be_bytes(take(&mut bytes)?);
    let digest = take(&mut bytes)?;
    if identity.0 == [0; 16] || identity.1 == [0; 16] || generation == 0 || digest == [0; 32] {
        return Err(RuntimeGenerationError::CorruptState);
    }
    Ok((identity, (generation, digest)))
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], RuntimeGenerationError> {
    let (prefix, remaining) = bytes
        .split_at_checked(N)
        .ok_or(RuntimeGenerationError::CorruptState)?;
    let value = prefix
        .try_into()
        .map_err(|_| RuntimeGenerationError::CorruptState)?;
    *bytes = remaining;
    Ok(value)
}
