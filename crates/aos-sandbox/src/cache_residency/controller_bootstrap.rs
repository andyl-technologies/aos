//! Protected controller source for cache Replay authority bootstrap.
//!
//! A dedicated owner-checked controller journal contains one immutable
//! canonical replay manifest per partition. Each import appends all new
//! partition records in one transaction under keys made from exact partition
//! digests. Replacements, deletions, foreign namespaces, and partial recovery
//! are rejected before any target authority can be issued. The manifest
//! carries complete node and project quotas; publisher byte/object policy
//! cannot stand in for its pin-class limits.
//!
//! ```text
//! key:   NUL "aos-cache-controller-bootstrap-v1" NUL partition-digest:32
//! value: canonical AOSCRM01 replay manifest
//! manifest record key: NUL "aos-cache-replay-authority-v1" NUL partition-digest:32
//! ```
//!
//! A trusted controller credential may append these immutable records through
//! the canonical bundle importer. Its framing is:
//!
//! ```text
//! AOSCRB01 | version:u16=1 | count:u16 | reserved:u32=0
//! repeated count times: manifest_length:u32 | canonical AOSCRM01 manifest
//! SHA-256("aos.sandbox.cache.controller-bundle.v1\0" || preceding bytes)
//! ```

use std::{collections::BTreeMap, path::Path};

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::journal::{
    Journal, JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
    RecoveryReport,
};

use super::protected_owner::{
    decode_cache_replay_manifest, encode_cache_replay_manifest, validate_genesis_checkpoint,
};
use super::{
    CacheAuthorityPurposeV1, CacheGlobalRecoveryStateV1, CacheHistoryFloorV1,
    CacheRecoveryInventoryV1, CacheRecoveryLimitsV1, CacheResidencyProtectedJournalErrorV1,
    CacheResidencyReplayPartitionEvidenceV1, CacheTypedCheckpointV1, NodeCacheQuotaV1,
    PhysicalPartitionId, ProjectCacheQuotaV1, encode_typed_checkpoint,
};

const CONTROLLER_CACHE_ROOT: &str = "/var/lib/aos/sandboxd/cache-residency-authority";
const CONTROLLER_CACHE_JOURNAL: &str = "bootstrap-v1.journal";
const SOURCE_KEY_PREFIX: &[u8] = b"\0aos-cache-controller-bootstrap-v1\0";
const AUTHORITY_KEY_PREFIX: &[u8] = b"\0aos-cache-replay-authority-v1\0";
const MAXIMUM_SOURCE_PARTITIONS: usize = 4_096;
const BUNDLE_MAGIC: &[u8; 8] = b"AOSCRB01";
const BUNDLE_DOMAIN: &[u8] = b"aos.sandbox.cache.controller-bundle.v1\0";
const MAXIMUM_BUNDLE_BYTES: usize = 64 * 1024 * 1024;

/// Reports a missing, modified, or noncanonical protected cache source.
#[derive(Debug, thiserror::Error)]
pub enum CacheReplayControllerBootstrapErrorV1 {
    /// Fixed owner-checked journal access or replay failed.
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
    owner_uid: u32,
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
        Self::open_fixed_protected_for_uid(0)
    }

    /// Opens the fixed source under an exact configured service UID.
    ///
    /// # Errors
    ///
    /// Returns [`CacheReplayControllerBootstrapErrorV1`] for unsafe ownership,
    /// invalid source history, or noncanonical partition evidence.
    pub fn open_fixed_protected_for_uid(
        owner_uid: u32,
    ) -> Result<(Self, RecoveryReport), CacheReplayControllerBootstrapErrorV1> {
        let (mut journal, report) = Journal::open_protected_at_for_uid(
            Path::new(CONTROLLER_CACHE_ROOT),
            CONTROLLER_CACHE_JOURNAL,
            controller_cache_journal_limits(),
            owner_uid,
        )?;
        if report.truncated_bytes != 0 {
            return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
        }
        let records = read_source_records(&mut journal)?;
        if records.is_empty()
            || report.committed_transactions == 0
            || report.committed_transactions > records.len()
            || report.committed_records != records.len()
        {
            return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
        }
        Ok((
            Self {
                journal,
                records,
                owner_uid,
            },
            report,
        ))
    }

    /// Imports an exact trusted controller credential without replacing source history.
    ///
    /// The caller must obtain `bundle` from its protected systemd credential,
    /// not a public request. A clean pre-commit absence is retriable with the
    /// same bundle; a partial journal tail, changed record, or omitted existing
    /// partition fails closed.
    ///
    /// # Errors
    ///
    /// Returns [`CacheReplayControllerBootstrapErrorV1`] for malformed bundle
    /// bytes, unsafe storage, source-history divergence, or failed readback.
    pub fn import_fixed_bundle_for_uid(
        owner_uid: u32,
        bundle: &[u8],
    ) -> Result<RecoveryReport, CacheReplayControllerBootstrapErrorV1> {
        let requested = decode_controller_bundle(bundle)?;
        let (mut journal, report) = Journal::open_protected_at_for_uid(
            Path::new(CONTROLLER_CACHE_ROOT),
            CONTROLLER_CACHE_JOURNAL,
            controller_cache_journal_limits(),
            owner_uid,
        )?;
        let existing = read_source_records(&mut journal)?;
        if report.truncated_bytes != 0
            || report.committed_transactions > existing.len()
            || (!existing.is_empty() && report.committed_transactions == 0)
            || report.committed_records != existing.len()
            || existing
                .iter()
                .any(|(partition, bytes)| requested.get(partition) != Some(bytes))
        {
            return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
        }

        let missing = requested
            .iter()
            .filter(|(partition, _)| !existing.contains_key(partition))
            .map(|(partition, bytes)| {
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    source_key(*partition),
                    bytes.clone(),
                )
            })
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            let digest = Sha256::new()
                .chain_update(b"aos.sandbox.cache.controller-source-transaction.v1\0")
                .chain_update(bundle)
                .finalize();
            let transaction_id: [u8; 16] = digest[..16]
                .try_into()
                .map_err(|_| CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
            let transaction = JournalTransaction::new(transaction_id, missing)?;
            let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
            for (partition, _) in requested
                .iter()
                .filter(|(partition, _)| !existing.contains_key(partition))
            {
                if authority.get(&source_key(*partition))?.is_some() {
                    return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
                }
            }
            let preflight = authority.preflight_transactions(std::slice::from_ref(&transaction))?;
            authority
                .validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;
            authority.commit(&transaction)?;
            for (partition, bytes) in requested
                .iter()
                .filter(|(partition, _)| !existing.contains_key(partition))
            {
                if authority.get(&source_key(*partition))? != Some(bytes.as_slice()) {
                    return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
                }
            }
        }
        drop(journal);

        let (owner, final_report) = Self::open_fixed_protected_for_uid(owner_uid)?;
        if owner.records != requested {
            return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
        }
        Ok(final_report)
    }

    /// Lists the exact partitions retained by this immutable controller source.
    #[must_use]
    pub fn partitions(&self) -> impl Iterator<Item = ObjectDigest> + '_ {
        self.records.keys().copied()
    }

    pub(crate) const fn owner_uid(&self) -> u32 {
        self.owner_uid
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
        if records.len() >= MAXIMUM_SOURCE_PARTITIONS {
            return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
        }
        let partition = validate_source_record(key, bytes, limits)?;
        if records.insert(partition, bytes.to_vec()).is_some() {
            return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
        }
    }
    Ok(records)
}

fn validate_source_record(
    key: &[u8],
    bytes: &[u8],
    limits: CacheRecoveryLimitsV1,
) -> Result<ObjectDigest, CacheReplayControllerBootstrapErrorV1> {
    if !key.starts_with(SOURCE_KEY_PREFIX) || key.len() != SOURCE_KEY_PREFIX.len() + 32 {
        return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
    }
    let evidence = decode_cache_replay_manifest(bytes, limits)
        .map_err(|_| CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
    let partition = evidence.partition.digest();
    if evidence.purpose != CacheAuthorityPurposeV1::Replay
        || evidence.prior_typed_checkpoint.is_some()
        || key != source_key(partition)
        || evidence.record_key != replay_authority_key(partition)
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
    if derived != evidence.scope {
        return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
    }
    Ok(partition)
}

fn source_key(partition: ObjectDigest) -> Vec<u8> {
    let mut key = Vec::with_capacity(SOURCE_KEY_PREFIX.len() + 32);
    key.extend_from_slice(SOURCE_KEY_PREFIX);
    key.extend_from_slice(partition.as_bytes());
    key
}

/// Builds a canonical empty-partition Replay manifest from complete cache quotas.
///
/// The caller must supply independently approved node and project pin-class
/// ceilings as well as byte/object limits. This encoder does not issue Replay
/// authority; the manifest must enter controller custody through the trusted
/// bundle credential and immutable source journal.
///
/// # Errors
///
/// Returns [`CacheReplayControllerBootstrapErrorV1`] for incoherent quotas,
/// duplicate project quotas, invalid validity, or over-bound encoded state.
pub fn encode_cache_replay_genesis_manifest_v1(
    partition: PhysicalPartitionId,
    node_quota: NodeCacheQuotaV1,
    mut project_quotas: Vec<ProjectCacheQuotaV1>,
    valid_until: u64,
) -> Result<Vec<u8>, CacheReplayControllerBootstrapErrorV1> {
    let limits = CacheRecoveryLimitsV1::default();
    project_quotas.sort_by_key(|quota| *quota.project.as_bytes());
    let global = CacheGlobalRecoveryStateV1::new(
        node_quota,
        project_quotas,
        Vec::new(),
        Vec::new(),
        None,
        None,
        Vec::new(),
        Vec::new(),
        None,
        limits,
    )
    .map_err(|_| CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
    let history_head = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.cache.controller-genesis-history.v1\0")
            .chain_update(partition.digest().as_bytes())
            .finalize()
            .into(),
    );
    let typed = CacheTypedCheckpointV1::from_baselines(
        1,
        history_head,
        ObjectDigest::from_bytes([0; 32]),
        Vec::new(),
        Vec::new(),
        global,
        partition,
        limits,
    )
    .map_err(|_| CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
    let typed_checkpoint = encode_typed_checkpoint(&typed, partition, limits)
        .map_err(|_| CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
    let floor = CacheHistoryFloorV1::new(
        2,
        typed.checkpoint.digest,
        ObjectDigest::from_bytes([0; 32]),
        history_head,
    )
    .map_err(|_| CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
    let scope = CacheRecoveryInventoryV1::replay_authority_scope(
        partition,
        &typed_checkpoint,
        None,
        floor,
        valid_until,
        limits,
    )
    .map_err(|_| CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
    let evidence = CacheResidencyReplayPartitionEvidenceV1 {
        partition,
        purpose: CacheAuthorityPurposeV1::Replay,
        scope,
        record_key: replay_authority_key(partition.digest()),
        typed_checkpoint,
        prior_typed_checkpoint: None,
        floor,
    };
    let manifest = encode_cache_replay_manifest(&evidence, limits)?;
    validate_source_record(&source_key(partition.digest()), &manifest, limits)?;
    Ok(manifest)
}

/// Encodes canonical Replay manifests as one bounded controller credential.
///
/// The output is sorted by physical partition digest. A caller must still
/// supply the resulting bytes through a trusted credential path; encoding
/// them does not issue authority.
///
/// # Errors
///
/// Returns [`CacheReplayControllerBootstrapErrorV1`] for invalid, duplicate,
/// empty, or over-bound input.
pub fn encode_cache_replay_controller_bundle_v1(
    manifests: impl IntoIterator<Item = Vec<u8>>,
) -> Result<Vec<u8>, CacheReplayControllerBootstrapErrorV1> {
    let mut records = BTreeMap::new();
    let mut bounded_bytes = 48_usize;
    let limits = CacheRecoveryLimitsV1::default();
    for manifest in manifests {
        bounded_bytes = bounded_bytes
            .checked_add(4)
            .and_then(|size| size.checked_add(manifest.len()))
            .filter(|size| *size <= MAXIMUM_BUNDLE_BYTES)
            .ok_or(CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
        let evidence = decode_cache_replay_manifest(&manifest, limits)
            .map_err(|_| CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
        let partition = evidence.partition.digest();
        validate_source_record(&source_key(partition), &manifest, limits)?;
        if records.insert(partition, manifest).is_some()
            || records.len() > MAXIMUM_SOURCE_PARTITIONS
        {
            return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
        }
    }
    if records.is_empty() {
        return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
    }

    let count = u16::try_from(records.len())
        .map_err(|_| CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(BUNDLE_MAGIC);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(&[0; 4]);
    for manifest in records.values() {
        let length = u32::try_from(manifest.len())
            .map_err(|_| CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
        if bytes
            .len()
            .checked_add(4)
            .and_then(|size| size.checked_add(manifest.len()))
            .and_then(|size| size.checked_add(32))
            .is_none_or(|size| size > MAXIMUM_BUNDLE_BYTES)
        {
            return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
        }
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(manifest);
    }
    let digest = Sha256::new()
        .chain_update(BUNDLE_DOMAIN)
        .chain_update(&bytes)
        .finalize();
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

fn decode_controller_bundle(
    bytes: &[u8],
) -> Result<BTreeMap<ObjectDigest, Vec<u8>>, CacheReplayControllerBootstrapErrorV1> {
    if bytes.len() < 48
        || bytes.len() > MAXIMUM_BUNDLE_BYTES
        || &bytes[..8] != BUNDLE_MAGIC
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[12..16] != [0; 4]
    {
        return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
    }
    let footer = bytes.len() - 32;
    let digest = Sha256::new()
        .chain_update(BUNDLE_DOMAIN)
        .chain_update(&bytes[..footer])
        .finalize();
    if bytes[footer..] != digest[..] {
        return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
    }
    let count =
        usize::from(u16::from_be_bytes(bytes[10..12].try_into().map_err(
            |_| CacheReplayControllerBootstrapErrorV1::InvalidSource,
        )?));
    if count == 0 || count > MAXIMUM_SOURCE_PARTITIONS {
        return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
    }

    let mut cursor = 16_usize;
    let mut records = BTreeMap::new();
    let mut previous = None;
    let limits = CacheRecoveryLimitsV1::default();
    for _ in 0..count {
        let length_end = cursor
            .checked_add(4)
            .filter(|end| *end <= footer)
            .ok_or(CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
        let length = usize::try_from(u32::from_be_bytes(
            bytes[cursor..length_end]
                .try_into()
                .map_err(|_| CacheReplayControllerBootstrapErrorV1::InvalidSource)?,
        ))
        .map_err(|_| CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
        cursor = length_end;
        let manifest_end = cursor
            .checked_add(length)
            .filter(|end| *end <= footer)
            .ok_or(CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
        let manifest = &bytes[cursor..manifest_end];
        let evidence = decode_cache_replay_manifest(manifest, limits)
            .map_err(|_| CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
        let partition = evidence.partition.digest();
        validate_source_record(&source_key(partition), manifest, limits)?;
        if previous.is_some_and(|previous| partition <= previous)
            || records.insert(partition, manifest.to_vec()).is_some()
        {
            return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
        }
        previous = Some(partition);
        cursor = manifest_end;
    }
    if cursor != footer {
        return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
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
        maximum_journal_bytes: 256 * 1024 * 1024,
        maximum_record_bytes: 16 * 1024 * 1024,
        maximum_transactions: MAXIMUM_SOURCE_PARTITIONS,
        maximum_materialized_bytes: 128 * 1024 * 1024,
        maximum_materialized_records: MAXIMUM_SOURCE_PARTITIONS,
        maximum_records_per_transaction: MAXIMUM_SOURCE_PARTITIONS,
        maximum_transaction_bytes: 128 * 1024 * 1024,
        ..JournalLimits::default()
    }
}
