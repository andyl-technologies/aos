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
    CacheResidencyReplayPartitionEvidenceV1, CacheTypedCheckpointV1, encode_typed_checkpoint,
};
use aos_sandbox_protocol::cache_state::{
    NodeCacheQuotaV1, PhysicalPartitionId, ProjectCacheQuotaV1,
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
    /// Native comparison failed; the separate final Source failure remains owned.
    #[cfg(target_os = "linux")]
    #[error("protected cache coverage native comparison failed: {first}")]
    CoverageNative {
        /// The unchanged first native comparison failure.
        #[source]
        first: JournalError,
        /// A later genuine original-Source bookend failure, if one occurred.
        final_source: Option<Box<CacheReplayControllerBootstrapErrorV1>>,
    },
}

/// Retains immutable, complete-partition bootstrap input from controller custody.
pub struct CacheReplayControllerBootstrapOwnerV1 {
    journal: Journal,
    records: BTreeMap<ObjectDigest, Vec<u8>>,
    owner_uid: u32,
}

pub(crate) fn open_existing_controller_cache_source(
    owner_uid: u32,
) -> Result<(Journal, RecoveryReport), JournalError> {
    Journal::open_existing_protected_at_for_uid(
        Path::new(CONTROLLER_CACHE_ROOT), CONTROLLER_CACHE_JOURNAL,
        controller_cache_journal_limits(), owner_uid,
    )
}

pub(crate) fn validate_controller_cache_source(
    journal: &mut Journal,
    report: &RecoveryReport,
) -> Result<BTreeMap<ObjectDigest, Vec<u8>>, CacheReplayControllerBootstrapErrorV1> {
    if report.truncated_bytes != 0 {
        return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
    }
    let records = read_source_records(journal)?;
    if records.is_empty()
        || report.committed_transactions == 0
        || report.committed_transactions > records.len()
        || report.committed_records != records.len()
    {
        return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
    }
    Ok(records)
}

impl CacheReplayControllerBootstrapOwnerV1 {
    // Copy only this fixed CacheBootstrap writer's native comparison DATA.
    // The borrowed loan ends here; its real writer and errors remain owned.
    #[cfg(target_os = "linux")]
    pub(crate) fn capture_git_coverage_native_cut_v1(
        &mut self,
        catalog: &aos_sandbox_core::format::git_upload_enrollment::GitCoverageCatalogV1<'_>,
    ) -> Result<crate::policy_compiler::GitCoverageNativeCutDataV1, CacheReplayControllerBootstrapErrorV1> {
        use aos_sandbox_core::format::git_upload_enrollment::GitCoverageJournalProfileV1;
        use crate::policy_compiler::GitCoverageNativeCutDataV1;

        self.recheck_existing()?;
        let returned = (|| {
            let mut native = self.journal.cache_bootstrap_coverage_native_prefix_v1(catalog)
                .map_err(|cause| JournalError::GitCoverageNativeHistory(Box::new(cause)))?;
            native.recheck()?;
            if native.last_commit().is_none() {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(GitCoverageNativeCutDataV1::from_original_loan(
                GitCoverageJournalProfileV1::CacheBootstrap, &native,
            ))
        })();
        let postcheck = self.recheck_existing();
        match (returned, postcheck) {
            (Ok(data), Ok(())) => Ok(data),
            (Err(first), final_source) => Err(CacheReplayControllerBootstrapErrorV1::CoverageNative {
                first,
                final_source: final_source.err().map(Box::new),
            }),
            (Ok(_), Err(cause)) => Err(cause),
        }
    }

    // Comparison DATA only. The existing complete manifest validator and
    // original fixed writer remain the sole provisioning/currentness engines.
    // The native loan checks actual UUIDs, PUT sequences and complete values;
    // it neither exports this Journal nor opens another name.
    #[cfg(target_os = "linux")]
    pub(crate) fn compare_git_coverage_catalog_v1(
        &mut self,
        catalog: &aos_sandbox_core::format::git_upload_enrollment::GitCoverageCatalogV1<'_>,
    ) -> Result<(), CacheReplayControllerBootstrapErrorV1> {
        self.recheck_existing()?;
        let returned = match self.journal.cache_bootstrap_coverage_native_prefix_v1(catalog) {
            Ok(mut native) => native.recheck(),
            Err(cause) => Err(JournalError::GitCoverageNativeHistory(Box::new(cause))),
        };
        // Run the final original-source check even when native comparison
        // returned a cause. Both genuine failures remain separately available.
        let postcheck = self.recheck_existing();
        match (returned, postcheck) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(first), final_source) => Err(CacheReplayControllerBootstrapErrorV1::CoverageNative {
                first,
                final_source: final_source.err().map(Box::new),
            }),
            (Ok(()), Err(cause)) => Err(cause),
        }
    }

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
        let records = validate_controller_cache_source(&mut journal, &report)?;
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
            let transaction = JournalTransaction::new(transaction_id, missing)
                .map_err(JournalError::from)?;
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

    pub(crate) fn capture_existing(
        original: &mut Option<(Journal, RecoveryReport)>,
        destination: &mut Option<Self>,
        owner_uid: u32,
    ) -> Result<(), CacheReplayControllerBootstrapErrorV1> {
        if destination.is_some() {
            return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
        }
        let (journal, report) = original.as_mut()
            .ok_or(CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
        let records = validate_controller_cache_source(journal, report)?;
        let Some((journal, _)) = original.take() else {
            return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
        };
        *destination = Some(Self { journal, records, owner_uid });
        Ok(())
    }

    pub(crate) fn recheck_existing(&mut self) -> Result<(), CacheReplayControllerBootstrapErrorV1> {
        self.journal.require_protected_named_location(
            Path::new(CONTROLLER_CACHE_ROOT), CONTROLLER_CACHE_JOURNAL,
            self.owner_uid, controller_cache_journal_limits(),
        )?;
        require_original_source_records(&mut self.journal, &self.records)?;
        Ok(())
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
        require_original_source_records(&mut self.journal, &self.records)?;
        let bytes = self
            .records
            .get(&partition)
            .ok_or(CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
        decode_cache_replay_manifest(bytes, CacheRecoveryLimitsV1::default())
            .map_err(|_| CacheReplayControllerBootstrapErrorV1::InvalidSource)
    }
}


// Original capture validated every canonical manifest before storing this map.
// Later checks compare the complete current bytes against those originals; the
// private writer cannot substitute a new manifest by presenting a digest.
fn require_original_source_records(
    journal: &mut Journal,
    original: &BTreeMap<ObjectDigest, Vec<u8>>,
) -> Result<(), CacheReplayControllerBootstrapErrorV1> {
    if journal
        .all_records()
        .any(|(namespace, _, _)| namespace != RecordNamespace::DesiredState)
    {
        return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
    }

    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    require_source_record_equality(authority.records()?, original)
}

// The iterator borrows the actual protected authority above. Keeping this pure
// byte comparison separate also permits boundary tests without issuing owners.
fn require_source_record_equality<'record>(
    records: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
    original: &BTreeMap<ObjectDigest, Vec<u8>>,
) -> Result<(), CacheReplayControllerBootstrapErrorV1> {
    if original.is_empty() || original.len() > MAXIMUM_SOURCE_PARTITIONS {
        return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
    }

    let mut count = 0_usize;
    let mut expected = original.iter();
    for (key, bytes) in records {
        count = count.checked_add(1)
            .filter(|count| *count <= MAXIMUM_SOURCE_PARTITIONS)
            .ok_or(CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
        if !key.starts_with(SOURCE_KEY_PREFIX)
            || key.len() != SOURCE_KEY_PREFIX.len() + 32
        {
            return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
        }

        let (partition, original_bytes) = expected.next()
            .ok_or(CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
        if key.get(SOURCE_KEY_PREFIX.len()..) != Some(partition.as_bytes().as_slice())
            || original_bytes.as_slice() != bytes
        {
            return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
        }
    }

    if count != original.len() || expected.next().is_some() {
        return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
    }
    Ok(())
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


#[cfg(test)]
mod original_source_tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use super::*;

    fn partition(index: u64) -> ObjectDigest {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&index.to_be_bytes());
        ObjectDigest::from_bytes(bytes)
    }

    // These bytes test exact comparison only; they never construct a bootstrap
    // owner or replace its required complete canonical capture validator.
    fn original() -> BTreeMap<ObjectDigest, Vec<u8>> {
        BTreeMap::from([(partition(1), b"original manifest bytes".to_vec())])
    }

    fn rows(original: &BTreeMap<ObjectDigest, Vec<u8>>) -> Vec<(Vec<u8>, Vec<u8>)> {
        original.iter().map(|(partition, bytes)| {
            (source_key(*partition), bytes.clone())
        }).collect()
    }

    fn compare(
        rows: &[(Vec<u8>, Vec<u8>)],
        original: &BTreeMap<ObjectDigest, Vec<u8>>,
    ) -> Result<(), CacheReplayControllerBootstrapErrorV1> {
        require_source_record_equality(
            rows.iter().map(|(key, bytes)| (key.as_slice(), bytes.as_slice())),
            original,
        )
    }

    #[test]
    fn borrowed_comparison_rejects_changed_missing_extra_and_orphan_records() {
        let original = original();
        let exact = rows(&original);

        assert!(compare(&exact, &original).is_ok());
        assert!(compare(&[], &original).is_err());

        let mut changed = exact.clone();
        changed[0].1[0] ^= 1;
        assert!(compare(&changed, &original).is_err());

        let mut extra = exact.clone();
        extra.push((source_key(partition(2)), b"extra".to_vec()));
        assert!(compare(&extra, &original).is_err());

        let mut orphan = exact.clone();
        orphan[0].0[0] ^= 1;
        assert!(compare(&orphan, &original).is_err());

        let mut tail = exact;
        tail[0].0.push(0);
        assert!(compare(&tail, &original).is_err());
    }

    #[test]
    fn fixed_partition_limit_and_count_are_checked_before_matching() {
        let original = (1..=MAXIMUM_SOURCE_PARTITIONS)
            .map(|index| (partition(index as u64), vec![1]))
            .collect::<BTreeMap<_, _>>();
        let exact = rows(&original);

        assert!(compare(&exact, &original).is_ok());
        assert!(compare(&exact[..exact.len() - 1], &original).is_err());

        let mut excessive = original;
        excessive.insert(partition((MAXIMUM_SOURCE_PARTITIONS + 1) as u64), vec![2]);
        assert!(compare(&rows(&excessive), &excessive).is_err());
        assert!(compare(&[], &BTreeMap::new()).is_err());
    }

    fn fixture() -> (tempfile::TempDir, Journal, BTreeMap<ObjectDigest, Vec<u8>>) {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(), "source.journal", controller_cache_journal_limits(), uid,
        ).unwrap();
        let original = original();
        let transaction = JournalTransaction::new([1; 16], vec![JournalRecord::put(
            RecordNamespace::DesiredState, source_key(partition(1)),
            original.get(&partition(1)).unwrap().clone(),
        )]).unwrap();
        journal.claim_protected_authority(RecordNamespace::DesiredState)
            .unwrap().commit(&transaction).unwrap();
        (directory, journal, original)
    }

    // The temporary-root check exercises the same native named-writer check;
    // production recheck_existing additionally requires its fixed original path.
    fn check_fixture(
        journal: &mut Journal,
        original: &BTreeMap<ObjectDigest, Vec<u8>>,
    ) -> Result<(), CacheReplayControllerBootstrapErrorV1> {
        journal.require_protected_names_current_for_test()?;
        require_original_source_records(journal, original)
    }

    #[test]
    fn committed_native_mutations_and_foreign_namespaces_are_not_hidden() {
        for case in 0..4 {
            let (_directory, mut journal, original) = fixture();
            assert!(check_fixture(&mut journal, &original).is_ok());
            let record = match case {
                0 => JournalRecord::put(RecordNamespace::DesiredState,
                    source_key(partition(1)), b"changed".to_vec()),
                1 => JournalRecord::delete(RecordNamespace::DesiredState, source_key(partition(1))),
                2 => JournalRecord::put(RecordNamespace::DesiredState,
                    source_key(partition(2)), b"extra".to_vec()),
                _ => JournalRecord::put(RecordNamespace::Operation,
                    b"foreign".to_vec(), b"foreign".to_vec()),
            };
            let transaction = JournalTransaction::new([2; 16], vec![record]).unwrap();
            journal.commit(&transaction).unwrap();

            assert!(check_fixture(&mut journal, &original).is_err());
        }
    }

    #[test]
    fn identical_file_and_lock_replacements_fail_native_name_check() {
        for suffix in ["", ".lock"] {
            let (directory, mut journal, original) = fixture();
            assert!(check_fixture(&mut journal, &original).is_ok());
            let named = directory.path().join(format!("source.journal{suffix}"));
            let retained = directory.path().join(format!("source.journal{suffix}.retained"));
            fs::rename(&named, &retained).unwrap();
            fs::copy(&retained, &named).unwrap();

            assert!(check_fixture(&mut journal, &original).is_err());
        }
    }
}
