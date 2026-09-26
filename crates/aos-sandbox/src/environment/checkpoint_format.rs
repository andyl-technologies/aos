//! Canonical reconstructing codecs for environment materialized checkpoints.
//!
//! ```text
//! AOSENVCP | version:1 | kind:1 | reserved:5 | floor-count:4 |
//! record-count:4 | history-digest:32 | floors | length-prefixed records |
//! checkpoint-digest:32
//! ```
//!
//! A checkpoint is a trusted compaction boundary: its materialized digest
//! authenticates generations whose predecessor records were deliberately
//! removed. Every retained record is still decoded through its canonical
//! bounded record codec before materialization.

use std::collections::BTreeMap;

use aos_sandbox_core::{ObjectDigest, Revision, SandboxId};
use sha2::{Digest as _, Sha256};

use super::{
    EnvironmentActivationCheckpointV1, EnvironmentActivationHistoryV1,
    EnvironmentGenerationCheckpointV1, EnvironmentGenerationHistoryV1, EnvironmentHistoryError,
    EnvironmentModelError, MAXIMUM_ENVIRONMENT_ACTIVATION_BYTES,
    MAXIMUM_ENVIRONMENT_ACTIVATION_RECORDS, MAXIMUM_ENVIRONMENT_HISTORY_BYTES,
    MAXIMUM_ENVIRONMENT_HISTORY_RECORDS,
    activation_format::{decode_environment_activation_v1, encode_environment_activation_v1},
    decode_environment_generation_v1, encode_environment_generation_v1,
    environment_manifest_digest_v1,
    lifecycle::{EnvironmentActivationTransactionV1, activation_history_digest},
    model::environment_history_digest,
};

const MAGIC: &[u8; 8] = b"AOSENVCP";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 56;
const DIGEST_BYTES: usize = 32;

/// Encodes a complete environment-generation checkpoint.
///
/// # Errors
///
/// Returns [`EnvironmentHistoryError`] for changed materialization, exceeded
/// bounds, unrepresentable lengths, or allocation failure.
pub fn encode_environment_generation_checkpoint_v1(
    checkpoint: &EnvironmentGenerationCheckpointV1,
) -> Result<Vec<u8>, EnvironmentHistoryError> {
    if checkpoint.digest != environment_history_digest(&checkpoint.history) {
        return Err(EnvironmentHistoryError::Conflict);
    }
    let mut records = Vec::new();
    records
        .try_reserve_exact(checkpoint.history.generations.len())
        .map_err(|_| EnvironmentHistoryError::Model(EnvironmentModelError::Allocation))?;
    for (manifest, _) in checkpoint.history.generations.values() {
        records.push(encode_environment_generation_v1(manifest)?);
    }
    encode_checkpoint(
        1,
        &checkpoint.history.floors,
        checkpoint.digest,
        &records,
        MAXIMUM_ENVIRONMENT_HISTORY_BYTES,
    )
    .map_err(EnvironmentHistoryError::Model)
}

/// Decodes a complete environment-generation checkpoint.
///
/// # Errors
///
/// Returns [`EnvironmentHistoryError`] for malformed bounds, duplicate keys,
/// changed record digests, or a changed materialized history commitment.
pub fn decode_environment_generation_checkpoint_v1(
    encoded: &[u8],
    verifier: &super::EnvironmentJournalVerifierV1,
) -> Result<EnvironmentGenerationCheckpointV1, EnvironmentHistoryError> {
    let accepted_record = checkpoint_record_digest(encoded)
        .filter(|digest| verifier.accepts_checkpoint(*digest))
        .ok_or(EnvironmentHistoryError::Conflict)?;
    let (floors, expected, records) = decode_checkpoint(
        encoded,
        1,
        MAXIMUM_ENVIRONMENT_HISTORY_RECORDS,
        MAXIMUM_ENVIRONMENT_HISTORY_BYTES,
    )?;
    let mut history = EnvironmentGenerationHistoryV1::default();
    history.floors = floors;
    for record in records {
        let manifest = decode_environment_generation_v1(record)?;
        let key = (manifest.sandbox(), manifest.generation());
        let digest = environment_manifest_digest_v1(&manifest)?;
        let length = encode_environment_generation_v1(&manifest)?.len();
        history.retained_bytes = history
            .retained_bytes
            .checked_add(length)
            .filter(|value| *value <= MAXIMUM_ENVIRONMENT_HISTORY_BYTES)
            .ok_or(EnvironmentHistoryError::Capacity)?;
        if history
            .generations
            .insert(key, (manifest.clone(), digest))
            .is_some()
        {
            return Err(EnvironmentHistoryError::Conflict);
        }
        match history.latest.get(&manifest.sandbox()) {
            Some((latest, _)) if latest.generation() >= manifest.generation() => {
                return Err(EnvironmentHistoryError::Conflict);
            }
            _ => {
                history
                    .latest
                    .insert(manifest.sandbox(), (manifest, digest));
            }
        }
    }
    if history.floors.iter().any(|(sandbox, floor)| {
        history
            .latest
            .get(sandbox)
            .is_none_or(|(manifest, _)| manifest.generation() != *floor)
    }) || environment_history_digest(&history) != expected
    {
        return Err(EnvironmentHistoryError::Conflict);
    }
    Ok(EnvironmentGenerationCheckpointV1 {
        history,
        digest: expected,
        accepted_record: Some(accepted_record),
    })
}

/// Encodes a complete environment-activation checkpoint.
///
/// # Errors
///
/// Returns [`EnvironmentModelError`] for changed materialization, exceeded
/// bounds, unrepresentable lengths, or allocation failure.
pub fn encode_environment_activation_checkpoint_v1(
    checkpoint: &EnvironmentActivationCheckpointV1,
) -> Result<Vec<u8>, EnvironmentModelError> {
    if checkpoint.digest != activation_history_digest(&checkpoint.history)? {
        return Err(EnvironmentModelError::InvalidModel);
    }
    let mut records = Vec::new();
    records
        .try_reserve_exact(checkpoint.history.records.len())
        .map_err(|_| EnvironmentModelError::Allocation)?;
    for record in checkpoint.history.records.values() {
        records.push(encode_environment_activation_v1(record)?);
    }
    encode_checkpoint(
        2,
        &checkpoint.history.floors,
        checkpoint.digest,
        &records,
        MAXIMUM_ENVIRONMENT_ACTIVATION_BYTES,
    )
}

/// Decodes an environment-activation checkpoint against retained manifests.
///
/// # Errors
///
/// Returns [`EnvironmentModelError`] for malformed bounds, unknown selectors,
/// duplicate records, or a changed materialized history commitment.
pub fn decode_environment_activation_checkpoint_v1(
    encoded: &[u8],
    manifests: &EnvironmentGenerationHistoryV1,
    verifier: &super::EnvironmentJournalVerifierV1,
) -> Result<EnvironmentActivationCheckpointV1, EnvironmentModelError> {
    let accepted_record = checkpoint_record_digest(encoded)
        .filter(|digest| verifier.accepts_checkpoint(*digest))
        .ok_or(EnvironmentModelError::CorruptEncoding)?;
    let (floors, expected, records) = decode_checkpoint(
        encoded,
        2,
        MAXIMUM_ENVIRONMENT_ACTIVATION_RECORDS,
        MAXIMUM_ENVIRONMENT_ACTIVATION_BYTES,
    )?;
    let mut history = EnvironmentActivationHistoryV1::default();
    history.floors = floors;
    for record in records {
        let activation = decode_environment_activation_v1(record, manifests)?;
        retain_activation(&mut history, activation, verifier)?;
    }
    for record in history.records.values() {
        record.validate_authenticated_lease_boots(verifier.boot_rollover())?;
    }
    for record in history.latest.values() {
        record.validate_current_leases_with_rollover(
            &verifier.current_time(),
            verifier.boot_rollover(),
        )?;
    }
    if history.floors.iter().any(|(sandbox, floor)| {
        history
            .latest
            .get(sandbox)
            .is_none_or(|record| record.revision() != *floor)
    }) || activation_history_digest(&history)? != expected
    {
        return Err(EnvironmentModelError::InvalidModel);
    }
    Ok(EnvironmentActivationCheckpointV1 {
        history,
        digest: expected,
        accepted_record: Some(accepted_record),
    })
}

fn retain_activation(
    history: &mut EnvironmentActivationHistoryV1,
    activation: EnvironmentActivationTransactionV1,
    verifier: &super::EnvironmentJournalVerifierV1,
) -> Result<(), EnvironmentModelError> {
    if history.latest.contains_key(&activation.sandbox()) {
        return history.apply_stored(activation, Some(verifier.boot_rollover()));
    }
    let key = (activation.sandbox(), activation.revision());
    let encoded_length = encode_environment_activation_v1(&activation)?.len();
    history.retained_bytes = history
        .retained_bytes
        .checked_add(encoded_length)
        .filter(|value| *value <= MAXIMUM_ENVIRONMENT_ACTIVATION_BYTES)
        .ok_or(EnvironmentModelError::InvalidModel)?;
    if history.records.insert(key, activation.clone()).is_some() {
        return Err(EnvironmentModelError::InvalidModel);
    }
    match history.latest.get(&activation.sandbox()) {
        Some(latest) if latest.revision() >= activation.revision() => {
            return Err(EnvironmentModelError::InvalidModel);
        }
        _ => {
            history.latest.insert(activation.sandbox(), activation);
        }
    }
    Ok(())
}

fn encode_checkpoint(
    kind: u8,
    floors: &BTreeMap<SandboxId, Revision>,
    history_digest: ObjectDigest,
    records: &[Vec<u8>],
    ceiling: usize,
) -> Result<Vec<u8>, EnvironmentModelError> {
    let floor_count =
        u32::try_from(floors.len()).map_err(|_| EnvironmentModelError::InvalidModel)?;
    let record_count =
        u32::try_from(records.len()).map_err(|_| EnvironmentModelError::InvalidModel)?;
    let fixed_length = HEADER_BYTES
        .checked_add(
            floors
                .len()
                .checked_mul(24)
                .ok_or(EnvironmentModelError::InvalidModel)?,
        )
        .ok_or(EnvironmentModelError::InvalidModel)?;
    let length = records
        .iter()
        .try_fold(fixed_length, |total, record| {
            total.checked_add(4)?.checked_add(record.len())
        })
        .and_then(|value| value.checked_add(DIGEST_BYTES))
        .filter(|value| *value <= ceiling)
        .ok_or(EnvironmentModelError::InvalidModel)?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(length)
        .map_err(|_| EnvironmentModelError::Allocation)?;
    encoded.extend_from_slice(MAGIC);
    encoded.extend_from_slice(&VERSION.to_be_bytes());
    encoded.push(kind);
    encoded.extend_from_slice(&[0; 5]);
    encoded.extend_from_slice(&floor_count.to_be_bytes());
    encoded.extend_from_slice(&record_count.to_be_bytes());
    encoded.extend_from_slice(history_digest.as_bytes());
    for (sandbox, revision) in floors {
        encoded.extend_from_slice(sandbox.as_bytes());
        encoded.extend_from_slice(&revision.get().to_be_bytes());
    }
    for record in records {
        let record_length =
            u32::try_from(record.len()).map_err(|_| EnvironmentModelError::InvalidModel)?;
        encoded.extend_from_slice(&record_length.to_be_bytes());
        encoded.extend_from_slice(record);
    }
    let digest = checkpoint_digest(&encoded);
    encoded.extend_from_slice(digest.as_bytes());
    Ok(encoded)
}

fn decode_checkpoint<'a>(
    encoded: &'a [u8],
    expected_kind: u8,
    record_ceiling: usize,
    byte_ceiling: usize,
) -> Result<(BTreeMap<SandboxId, Revision>, ObjectDigest, Vec<&'a [u8]>), EnvironmentModelError> {
    if encoded.len() < HEADER_BYTES + DIGEST_BYTES || encoded.len() > byte_ceiling {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    let (body, stored) = encoded.split_at(encoded.len() - DIGEST_BYTES);
    if checkpoint_digest(body).as_bytes() != stored {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    let mut preflight = body;
    if take::<8>(&mut preflight)? != *MAGIC
        || u16::from_be_bytes(take(&mut preflight)?) != VERSION
        || take::<1>(&mut preflight)?[0] != expected_kind
        || take::<5>(&mut preflight)? != [0; 5]
    {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    let floor_count = usize::try_from(u32::from_be_bytes(take(&mut preflight)?))
        .map_err(|_| EnvironmentModelError::CorruptEncoding)?;
    let record_count = usize::try_from(u32::from_be_bytes(take(&mut preflight)?))
        .map_err(|_| EnvironmentModelError::CorruptEncoding)?;
    if floor_count > record_ceiling || record_count > record_ceiling {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    let expected = ObjectDigest::from_bytes(take(&mut preflight)?);
    take_slice(
        &mut preflight,
        floor_count
            .checked_mul(24)
            .ok_or(EnvironmentModelError::CorruptEncoding)?,
    )?;
    for _ in 0..record_count {
        let length = usize::try_from(u32::from_be_bytes(take(&mut preflight)?))
            .map_err(|_| EnvironmentModelError::CorruptEncoding)?;
        if length == 0 || length > byte_ceiling {
            return Err(EnvironmentModelError::CorruptEncoding);
        }
        take_slice(&mut preflight, length)?;
    }
    if !preflight.is_empty() {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    let mut bytes = &body[HEADER_BYTES..];
    let mut floors = BTreeMap::new();
    for _ in 0..floor_count {
        let sandbox = SandboxId::from_bytes(take(&mut bytes)?);
        let revision = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
        if sandbox.as_bytes() == &[0; 16]
            || revision.get() == 0
            || revision.get() == u64::MAX
            || floors.insert(sandbox, revision).is_some()
        {
            return Err(EnvironmentModelError::CorruptEncoding);
        }
    }
    let mut records = Vec::new();
    records
        .try_reserve_exact(record_count)
        .map_err(|_| EnvironmentModelError::Allocation)?;
    for _ in 0..record_count {
        let length = usize::try_from(u32::from_be_bytes(take(&mut bytes)?))
            .map_err(|_| EnvironmentModelError::CorruptEncoding)?;
        records.push(take_slice(&mut bytes, length)?);
    }
    Ok((floors, expected, records))
}

fn checkpoint_digest(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.environment.checkpoint.v1\0")
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

fn checkpoint_record_digest(encoded: &[u8]) -> Option<ObjectDigest> {
    let (_, stored) = encoded.split_at_checked(encoded.len().checked_sub(DIGEST_BYTES)?)?;
    let bytes: [u8; DIGEST_BYTES] = stored.try_into().ok()?;
    Some(ObjectDigest::from_bytes(bytes))
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], EnvironmentModelError> {
    take_slice(bytes, N)?
        .try_into()
        .map_err(|_| EnvironmentModelError::CorruptEncoding)
}

fn take_slice<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8], EnvironmentModelError> {
    let (head, tail) = bytes
        .split_at_checked(length)
        .ok_or(EnvironmentModelError::CorruptEncoding)?;
    *bytes = tail;
    Ok(head)
}
