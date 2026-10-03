//! Exact borrowed Broker HEAD and purpose-closed transaction/hash geometry.
//!
//! Host complete-map HEADs remain solely in Core's original comparison engine.
//! These hashes and sequence estimates are DATA, not persistence or capacity
//! tokens. The private purpose selector accepts no caller domain or namespace.

use std::collections::BTreeSet;

use aos_sandbox::{JournalTransaction, RecordNamespace};
use sha2::{Digest as _, Sha256};

use super::{FloorCutV1, FloorErrorV1, RecordPurposeDataV1};

const HEAD_DOMAIN: &[u8] = b"aos.sandbox.broker-session.tpm-floor.head.v1\0";

/// Hashes the original sorted complete namespace-47 map without packet copies.
///
/// # Errors
///
/// Rejects empty/nonascending keys, count overflow and invalid cut sentinels.
pub(crate) fn broker_cut_from_records_v1<'a>(
    sequence: u64,
    records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<FloorCutV1, FloorErrorV1> {
    let mut digest = Sha256::new();
    digest.update(HEAD_DOMAIN);
    digest.update([RecordNamespace::BrokerSessionTraffic as u8]);
    digest.update(sequence.to_be_bytes());
    let mut predecessor: Option<&[u8]> = None;
    let mut count = 0_u64;
    for (key, value) in records {
        if key.is_empty() || predecessor.is_some_and(|old| old >= key) {
            return Err(FloorErrorV1::Encoding);
        }
        update_bytes(&mut digest, key)?;
        update_bytes(&mut digest, value)?;
        count = count.checked_add(1).ok_or(FloorErrorV1::Encoding)?;
        predecessor = Some(key);
    }
    digest.update(count.to_be_bytes());
    FloorCutV1::new(sequence, digest.finalize().into())
}

/// Hashes exact ordered Broker records under the unchanged fixed domain.
///
/// # Errors
///
/// Rejects foreign namespaces, empty/duplicate keys and unrepresentable lengths.
pub(crate) fn broker_transaction_digest_v1(
    transaction: &JournalTransaction,
) -> Result<[u8; 32], FloorErrorV1> {
    transaction_digest_v1(RecordPurposeDataV1::BrokerV1, [0; 32], transaction)
}

/// Walks exact ordered records using only a closed purpose's DATA domain.
///
/// # Errors
///
/// Rejects foreign namespaces, empty/duplicate keys and unrepresentable lengths.
pub(super) fn transaction_digest_v1(
    purpose: RecordPurposeDataV1,
    scope: [u8; 32],
    transaction: &JournalTransaction,
) -> Result<[u8; 32], FloorErrorV1> {
    let mut digest = Sha256::new();
    digest.update(purpose.transaction_domain());
    if purpose == RecordPurposeDataV1::RuntimeDeploymentV1 {
        digest.update(scope);
    }
    digest.update(transaction.id());
    digest.update(
        u64::try_from(transaction.records().len())
            .map_err(|_| FloorErrorV1::Encoding)?
            .to_be_bytes(),
    );
    let mut keys = BTreeSet::new();
    for record in transaction.records() {
        if record.namespace() != purpose.namespace()
            || record.key().is_empty()
            || !keys.insert(record.key())
        {
            return Err(FloorErrorV1::Encoding);
        }
        digest.update([record.namespace() as u8, u8::from(record.value().is_some())]);
        update_bytes(&mut digest, record.key())?;
        update_bytes(&mut digest, record.value().unwrap_or_default())?;
    }
    Ok(digest.finalize().into())
}

fn update_bytes(digest: &mut Sha256, bytes: &[u8]) -> Result<(), FloorErrorV1> {
    digest.update(
        u64::try_from(bytes.len())
            .map_err(|_| FloorErrorV1::Encoding)?
            .to_be_bytes(),
    );
    digest.update(bytes);
    Ok(())
}

/// Computes the original exact native frame successor without reserving it.
///
/// # Errors
///
/// Rejects count/sequence overflow and the exhausted sequence sentinel.
pub(crate) fn successor_sequence(
    sequence: u64,
    transaction: &JournalTransaction,
) -> Result<u64, FloorErrorV1> {
    let frames = u64::try_from(transaction.records().len())
        .ok()
        .and_then(|records| records.checked_add(2))
        .ok_or(FloorErrorV1::Successor)?;
    sequence
        .checked_add(frames)
        .filter(|next| *next != u64::MAX)
        .ok_or(FloorErrorV1::Successor)
}

/// Computes fixed prepare/finalize sidecar geometry without proving its history.
///
/// # Errors
///
/// Rejects ordinal zero, arithmetic overflow and the exhausted sequence sentinel.
pub(crate) fn sidecar_sequence_v1(ordinal: u64, pending: bool) -> Result<u64, FloorErrorV1> {
    ordinal
        .checked_sub(1)
        .and_then(|count| count.checked_mul(9))
        .and_then(|frames| frames.checked_add(if pending { 8 } else { 4 }))
        .filter(|sequence| *sequence != u64::MAX)
        .ok_or(FloorErrorV1::Encoding)
}

/// Hashes only byte DATA; closed callers retain their fixed domain constants.
pub(crate) fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    for part in parts {
        digest.update(part);
    }
    digest.finalize().into()
}
