//! Canonical trusted-baseline codec for lifecycle auxiliary replay.
//!
//! ```text
//! AOSLIFCP | version:1 | reserved:2 | record-count:4 |
//! materialized-digest:32 | (length:4 | auxiliary-record)* | digest:32
//! ```

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::{
    decode_lifecycle_auxiliary_record_v1, encode_lifecycle_auxiliary_record_v1,
    LifecycleAuxiliaryCheckpointV1, LifecycleAuxiliaryHistoryV1, LifecycleModelError,
    LifecycleReplayVerificationV1, MAXIMUM_LIFECYCLE_AUXILIARY_BYTES,
    MAXIMUM_LIFECYCLE_AUXILIARY_PAYLOAD_BYTES, MAXIMUM_LIFECYCLE_AUXILIARY_RECORDS,
};

const MAGIC: &[u8; 8] = b"AOSLIFCP";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 48;
const RECORD_HEADER_BYTES: usize = 244;
const DIGEST_BYTES: usize = 32;

impl LifecycleAuxiliaryCheckpointV1 {
    /// Returns the complete checkpoint commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }
}

impl LifecycleAuxiliaryHistoryV1 {
    pub(super) fn complete_digest(&self) -> Result<ObjectDigest, LifecycleModelError> {
        let mut hasher = Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.auxiliary-checkpoint.v2\0")
            .chain_update((self.retained_bytes as u64).to_be_bytes())
            .chain_update(self.operations.complete_digest()?.as_bytes())
            .chain_update(
                self.replay_floor
                    .map_or(0, aos_sandbox_core::Revision::get)
                    .to_be_bytes(),
            )
            .chain_update(
                self.replay_authority
                    .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
                    .as_bytes(),
            );
        for (key, record) in &self.records {
            hasher = hasher
                .chain_update(key.0.as_bytes())
                .chain_update(key.1.as_bytes())
                .chain_update([key.2 as u8])
                .chain_update(key.3.get().to_be_bytes())
                .chain_update(record.complete_digest().as_bytes());
        }
        for ((project, join), digest) in &self.joins {
            hasher = hasher
                .chain_update(project.as_bytes())
                .chain_update(join.as_bytes())
                .chain_update(digest.digest().as_bytes());
        }
        Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
    }
}

/// Encodes a complete lifecycle auxiliary checkpoint in baseline order.
///
/// # Errors
///
/// Returns [`LifecycleModelError`] for changed materialization, ceiling
/// exhaustion, unrepresentable lengths, or allocation failure.
pub fn encode_lifecycle_auxiliary_checkpoint_v1(
    checkpoint: &LifecycleAuxiliaryCheckpointV1,
) -> Result<Vec<u8>, LifecycleModelError> {
    if checkpoint.digest != checkpoint.history.complete_digest()? {
        return Err(LifecycleModelError::InvalidModel);
    }
    let mut records = Vec::new();
    records
        .try_reserve_exact(checkpoint.history.order.len())
        .map_err(|_| LifecycleModelError::Allocation)?;
    for key in &checkpoint.history.order {
        let record = checkpoint
            .history
            .records
            .get(key)
            .ok_or(LifecycleModelError::InvalidModel)?;
        records.push(encode_lifecycle_auxiliary_record_v1(record)?);
    }
    let length = records
        .iter()
        .try_fold(HEADER_BYTES, |total, record| {
            total.checked_add(4)?.checked_add(record.len())
        })
        .and_then(|value| value.checked_add(DIGEST_BYTES))
        .filter(|value| *value <= MAXIMUM_LIFECYCLE_AUXILIARY_BYTES)
        .ok_or(LifecycleModelError::InvalidModel)?;
    let count = u32::try_from(records.len()).map_err(|_| LifecycleModelError::InvalidModel)?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(length)
        .map_err(|_| LifecycleModelError::Allocation)?;
    encoded.extend_from_slice(MAGIC);
    encoded.extend_from_slice(&VERSION.to_be_bytes());
    encoded.extend_from_slice(&[0; 2]);
    encoded.extend_from_slice(&count.to_be_bytes());
    encoded.extend_from_slice(checkpoint.digest.as_bytes());
    for record in records {
        encoded.extend_from_slice(
            &u32::try_from(record.len())
                .map_err(|_| LifecycleModelError::InvalidModel)?
                .to_be_bytes(),
        );
        encoded.extend_from_slice(&record);
    }
    let digest = checkpoint_digest(&encoded);
    encoded.extend_from_slice(digest.as_bytes());
    Ok(encoded)
}

/// Decodes and reconstructs a trusted compacted auxiliary baseline.
///
/// # Errors
///
/// Returns [`LifecycleModelError`] for malformed bounds, changed digest,
/// verifier mismatch, or an orphaned/cross-projection-inconsistent record.
pub fn decode_lifecycle_auxiliary_checkpoint_v1(
    encoded: &[u8],
    verification: &LifecycleReplayVerificationV1,
) -> Result<LifecycleAuxiliaryCheckpointV1, LifecycleModelError> {
    if encoded.len() < HEADER_BYTES + DIGEST_BYTES
        || encoded.len() > MAXIMUM_LIFECYCLE_AUXILIARY_BYTES
    {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let (body, stored) = encoded.split_at(encoded.len() - DIGEST_BYTES);
    let digest = checkpoint_digest(body);
    if digest.as_bytes() != stored || !verification.accepts_checkpoint(digest) {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let mut preflight = body;
    if take::<8>(&mut preflight)? != *MAGIC
        || u16::from_be_bytes(take(&mut preflight)?) != VERSION
        || take::<2>(&mut preflight)? != [0; 2]
    {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let count = usize::try_from(u32::from_be_bytes(take(&mut preflight)?))
        .map_err(|_| LifecycleModelError::CorruptEncoding)?;
    if count > MAXIMUM_LIFECYCLE_AUXILIARY_RECORDS {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let expected = ObjectDigest::from_bytes(take(&mut preflight)?);
    for _ in 0..count {
        let length = usize::try_from(u32::from_be_bytes(take(&mut preflight)?))
            .map_err(|_| LifecycleModelError::CorruptEncoding)?;
        if length < RECORD_HEADER_BYTES + 1 + DIGEST_BYTES
            || length
                > RECORD_HEADER_BYTES + MAXIMUM_LIFECYCLE_AUXILIARY_PAYLOAD_BYTES + DIGEST_BYTES
        {
            return Err(LifecycleModelError::CorruptEncoding);
        }
        take_slice(&mut preflight, length)?;
    }
    if !preflight.is_empty() {
        return Err(LifecycleModelError::CorruptEncoding);
    }

    let mut bytes = &body[HEADER_BYTES..];
    let mut records = Vec::new();
    records
        .try_reserve_exact(count)
        .map_err(|_| LifecycleModelError::Allocation)?;
    for _ in 0..count {
        let length = usize::try_from(u32::from_be_bytes(take(&mut bytes)?))
            .map_err(|_| LifecycleModelError::CorruptEncoding)?;
        records.push(decode_lifecycle_auxiliary_record_v1(
            take_slice(&mut bytes, length)?,
            verification,
        )?);
    }
    let history = LifecycleAuxiliaryHistoryV1::from_checkpoint_records(records, verification)?;
    if history.complete_digest()? != expected {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    Ok(LifecycleAuxiliaryCheckpointV1 {
        history,
        digest: expected,
        accepted_record: Some(digest),
    })
}

fn checkpoint_digest(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.auxiliary-checkpoint-record.v1\0")
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], LifecycleModelError> {
    take_slice(bytes, N)?
        .try_into()
        .map_err(|_| LifecycleModelError::CorruptEncoding)
}

fn take_slice<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8], LifecycleModelError> {
    let (head, tail) = bytes
        .split_at_checked(length)
        .ok_or(LifecycleModelError::CorruptEncoding)?;
    *bytes = tail;
    Ok(head)
}
