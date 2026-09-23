//! Protected controller source for cache Replay authority bootstrap.
//!
//! A dedicated root-owned journal contains one immutable canonical replay
//! manifest per partition. Each record is a single transaction under a key
//! made from the exact partition digest. Replacements, deletions, foreign
//! namespaces, and partial recovery are rejected before any target authority
//! can be issued. The manifest carries the complete node and project quotas;
//! publisher byte/object policy cannot stand in for its pin-class limits.
//!
//! ```text
//! key:   NUL "aos-cache-controller-bootstrap-v1" NUL partition-digest:32
//! value: canonical AOSCRM01 replay manifest
//! manifest record key: NUL "aos-cache-replay-authority-v1" NUL partition-digest:32
//! ```

use std::{collections::BTreeMap, path::Path};

use aos_sandbox_core::ObjectDigest;

use crate::journal::{Journal, JournalError, JournalLimits, RecordNamespace, RecoveryReport};

use super::protected_owner::{decode_cache_replay_manifest, validate_genesis_checkpoint};
use super::{
    CacheAuthorityPurposeV1, CacheRecoveryInventoryV1, CacheRecoveryLimitsV1,
    CacheResidencyProtectedJournalErrorV1, CacheResidencyReplayPartitionEvidenceV1,
};

const CONTROLLER_CACHE_ROOT: &str = "/var/lib/aos/controller/cache-residency-authority";
const CONTROLLER_CACHE_JOURNAL: &str = "bootstrap-v1.journal";
const SOURCE_KEY_PREFIX: &[u8] = b"\0aos-cache-controller-bootstrap-v1\0";
const AUTHORITY_KEY_PREFIX: &[u8] = b"\0aos-cache-replay-authority-v1\0";
const MAXIMUM_SOURCE_PARTITIONS: usize = 4_096;

/// Reports a missing, modified, or noncanonical protected cache source.
#[derive(Debug, thiserror::Error)]
pub enum CacheReplayControllerBootstrapErrorV1 {
    /// Fixed root-owned journal access or replay failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The target cache owner rejected an authority or manifest operation.
    #[error(transparent)]
    Target(#[from] CacheResidencyProtectedJournalErrorV1),
    /// The source contains foreign, mutable, incomplete, or invalid records.
    #[error("protected cache Replay bootstrap source is invalid")]
    InvalidSource,
}

/// Retains immutable, complete-partition bootstrap input from controller custody.
pub struct CacheReplayControllerBootstrapOwnerV1 {
    journal: Journal,
    records: BTreeMap<ObjectDigest, Vec<u8>>,
}

impl CacheReplayControllerBootstrapOwnerV1 {
    /// Opens and authenticates the fixed controller-side cache source journal.
    ///
    /// # Errors
    ///
    /// Returns [`CacheReplayControllerBootstrapErrorV1`] for unsafe storage,
    /// missing partitions, noncanonical manifests, or mutable source history.
    pub fn open_fixed_protected()
    -> Result<(Self, RecoveryReport), CacheReplayControllerBootstrapErrorV1> {
        let (mut journal, report) = Journal::open_protected_at(
            Path::new(CONTROLLER_CACHE_ROOT),
            CONTROLLER_CACHE_JOURNAL,
            controller_cache_journal_limits(),
        )?;
        if report.truncated_bytes != 0 {
            return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
        }
        let records = read_source_records(&mut journal)?;
        if records.is_empty()
            || report.committed_transactions != records.len()
            || report.committed_records != records.len()
        {
            return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
        }
        Ok((Self { journal, records }, report))
    }

    /// Rechecks the exact retained controller record for one partition.
    ///
    /// This returns source data only. The target cache owner must independently
    /// verify and durably install the matching Replay authority record.
    ///
    /// # Errors
    ///
    /// Returns [`CacheReplayControllerBootstrapErrorV1`] if protected current
    /// state differs from the opened source or the partition is absent.
    pub(crate) fn current_partition(
        &mut self,
        partition: ObjectDigest,
    ) -> Result<CacheResidencyReplayPartitionEvidenceV1, CacheReplayControllerBootstrapErrorV1>
    {
        if read_source_records(&mut self.journal)? != self.records {
            return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
        }
        let bytes = self
            .records
            .get(&partition)
            .ok_or(CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
        decode_cache_replay_manifest(bytes, CacheRecoveryLimitsV1::default())
            .map_err(|_| CacheReplayControllerBootstrapErrorV1::InvalidSource)
    }
}

fn read_source_records(
    journal: &mut Journal,
) -> Result<BTreeMap<ObjectDigest, Vec<u8>>, CacheReplayControllerBootstrapErrorV1> {
    if journal
        .all_records()
        .any(|(namespace, _, _)| namespace != RecordNamespace::DesiredState)
    {
        return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
    }
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let mut records = BTreeMap::new();
    let limits = CacheRecoveryLimitsV1::default();
    for (key, bytes) in authority.records()? {
        if records.len() >= MAXIMUM_SOURCE_PARTITIONS
            || !key.starts_with(SOURCE_KEY_PREFIX)
            || key.len() != SOURCE_KEY_PREFIX.len() + 32
        {
            return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
        }
        let evidence = decode_cache_replay_manifest(bytes, limits)
            .map_err(|_| CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
        if evidence.purpose != CacheAuthorityPurposeV1::Replay
            || evidence.prior_typed_checkpoint.is_some()
            || key[SOURCE_KEY_PREFIX.len()..] != *evidence.partition.digest().as_bytes()
            || evidence.record_key != replay_authority_key(evidence.partition.digest())
        {
            return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
        }
        validate_genesis_checkpoint(
            evidence.partition,
            &evidence.typed_checkpoint,
            evidence.floor,
            limits,
        )
        .map_err(|_| CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
        let derived = CacheRecoveryInventoryV1::replay_authority_scope(
            evidence.partition,
            &evidence.typed_checkpoint,
            None,
            evidence.floor,
            evidence.scope.valid_until(),
            limits,
        )
        .map_err(|_| CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
        if derived != evidence.scope
            || records
                .insert(evidence.partition.digest(), bytes.to_vec())
                .is_some()
        {
            return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
        }
    }
    Ok(records)
}

pub(super) fn replay_authority_key(partition: ObjectDigest) -> Vec<u8> {
    let mut key = Vec::with_capacity(AUTHORITY_KEY_PREFIX.len() + 32);
    key.extend_from_slice(AUTHORITY_KEY_PREFIX);
    key.extend_from_slice(partition.as_bytes());
    key
}

fn controller_cache_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_record_bytes: 16 * 1024 * 1024,
        maximum_materialized_records: MAXIMUM_SOURCE_PARTITIONS,
        maximum_records_per_transaction: 1,
        ..JournalLimits::default()
    }
}
