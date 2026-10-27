//! Shares Cache Git-history comparisons without native or clock authority.
//!
//! The actual Cache owner retains its held writer, full semantic replay,
//! original native prefix and independently owed bookends. These functions
//! inspect already parsed transactions only. They preserve the fixed policy
//! Genesis/birth recipe and the same monotone Clock chain; a signed catalog
//! cannot relabel later clock floors as new infrastructure.

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;
use aos_sandbox_model::{ObjectDigest, RecordNamespace};
use aos_sandbox_model::format::git_upload_enrollment::{
    GitCoverageBirthV1, GitCoverageFenceV1, GitCoverageOwnerKindV1,
};
use aos_sandbox_protocol::cache_state::clock_floor::{
    CACHE_CLOCK_KEY, cache_clock_transaction_id_data_v1, decode_cache_clock_floor,
};
use aos_sandbox_protocol::cache_state::fixed_journals::{
    CACHE_HOLD_GENESIS_KEY_V1 as GENESIS_KEY, CACHE_HOLD_GENESIS_V1 as GENESIS,
};
use aos_sandbox_protocol::cache_state::hold_state::{GIT_BIRTH_KEY, GIT_FENCE_KEY};
use aos_sandbox_protocol::cache_state::replay_evidence::cache_fixed_owner_scope_data_v1;
use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};
use sha2::{Digest as _, Sha256};

const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.cache-policy-hold-transaction.v1\0";

/// Encodes the existing deterministic one-PUT Cache policy transaction DATA.
///
/// # Errors
/// Preserves the original fixed transaction identifier and record validation.
pub fn policy_hold_transaction_data_v1(
    key: &[u8],
    value: &[u8],
) -> Result<JournalTransaction, JournalError> {
    let digest = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(key)
        .chain_update(value)
        .finalize();
    JournalTransaction::new(
        digest[..16]
            .try_into()
            .map_err(|_| JournalError::ProtectedBoundary)?,
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            key.to_vec(),
            value.to_vec(),
        )],
    ).map_err(JournalError::from)
}

/// Compares the actual policy Genesis and sole paired Git birth transaction.
///
/// The caller supplies coordinates from its same full native replay. This
/// comparison cannot open a writer or establish a current role grant.
///
/// # Errors
/// Refuses wrong order, extra transactions, altered records or prefix/birth
/// coordinates while preserving the original protected-boundary category.
pub fn require_policy_native_transaction_v1(
    index: usize,
    observed: &JournalTransaction,
    commit_sequence: u64,
    predecessor_prefix: [u8; 32],
) -> Result<(), JournalError> {
    if index == 0 {
        let expected = policy_hold_transaction_data_v1(GENESIS_KEY, GENESIS)?;
        if observed != &expected || commit_sequence != 3 {
            return Err(JournalError::ProtectedBoundary);
        }
        return Ok(());
    }
    if index != 1 || observed.records().len() != 2 {
        return Err(JournalError::ProtectedBoundary);
    }
    let [birth_record, fence_record] = observed.records() else {
        return Err(JournalError::ProtectedBoundary);
    };
    if birth_record.namespace() != RecordNamespace::DesiredState
        || fence_record.namespace() != RecordNamespace::DesiredState
        || birth_record.key() != GIT_BIRTH_KEY
        || fence_record.key() != GIT_FENCE_KEY
    {
        return Err(JournalError::ProtectedBoundary);
    }
    let birth = GitCoverageBirthV1::decode(
        birth_record.value().ok_or(JournalError::ProtectedBoundary)?,
    ).map_err(|_| JournalError::ProtectedBoundary)?;
    let fence = GitCoverageFenceV1::decode(
        fence_record.value().ok_or(JournalError::ProtectedBoundary)?,
    ).map_err(|_| JournalError::ProtectedBoundary)?;
    fence.compare_birth(&birth).map_err(|_| JournalError::ProtectedBoundary)?;
    if birth.fields().owner != GitCoverageOwnerKindV1::CacheAuthority
        || birth.fields().transaction != *observed.id()
        || fence.fields().transaction != *observed.id()
        || birth.fields().commit_sequence != commit_sequence
        || birth.fields().predecessor_prefix != predecessor_prefix
        || fence.fields().predecessor_prefix != predecessor_prefix
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

/// Compares one actual Clock floor against its complete prior revision.
///
/// This checks the existing parsed transaction and fixed Cache owner scope.
/// The caller independently runs its native replay and physical bookends.
///
/// # Errors
/// Refuses wrong keys, codecs, identifiers, scope, revision or monotone time
/// while preserving the original protected-boundary error category.
pub fn compare_clock_native_transaction_v1(
    transaction: &JournalTransaction,
    previous: Option<(ObjectDigest, u64, u64)>,
) -> Result<(ObjectDigest, u64, u64), JournalError> {
    let [record] = transaction.records() else {
        return Err(JournalError::ProtectedBoundary);
    };
    if record.namespace() != RecordNamespace::DesiredState || record.key() != CACHE_CLOCK_KEY {
        return Err(JournalError::ProtectedBoundary);
    }
    let value = record.value().ok_or(JournalError::ProtectedBoundary)?;
    let current = decode_cache_clock_floor(value)
        .map_err(|_| JournalError::ProtectedBoundary)?;
    let expected_transaction = cache_clock_transaction_id_data_v1(value)
        .map_err(|_| JournalError::ProtectedBoundary)?;
    if current.owner_scope != cache_fixed_owner_scope_data_v1()
        || transaction.id() != &expected_transaction
    {
        return Err(JournalError::ProtectedBoundary);
    }

    let successor = match previous {
        None => current.revision == 1 && current.predecessor_unix_seconds == 0,
        Some((scope, revision, observed)) => {
            scope == current.owner_scope
                && revision.checked_add(1) == Some(current.revision)
                && current.predecessor_unix_seconds == observed
                && current.observed_unix_seconds >= observed
        }
    };
    if !successor {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok((
        current.owner_scope,
        current.revision,
        current.observed_unix_seconds,
    ))
}
