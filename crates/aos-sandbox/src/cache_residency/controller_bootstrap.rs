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
    borrow_cache_replay_manifest, decode_cache_replay_manifest, encode_cache_replay_manifest,
    validate_genesis_checkpoint, genesis_manifest_project_count,
};
use super::{
    CacheAuthorityPurposeV1, CacheGlobalRecoveryStateV1, CacheHistoryFloorV1,
    CacheRecoveryInventoryV1, CacheRecoveryLimitsV1, CacheResidencyProtectedJournalErrorV1,
    CacheResidencyReplayPartitionEvidenceV1, CacheTypedCheckpointV1, encode_typed_checkpoint,
};
use aos_sandbox_protocol::cache_state::{
    NodeCacheQuotaV1, PhysicalPartitionId, ProjectCacheQuotaV1,
};

pub(crate) const CONTROLLER_CACHE_ROOT: &str = aos_sandbox_protocol::cache_state::fixed_journals::CACHE_BOOTSTRAP_DIRECTORY_V1;
pub(in crate::cache_residency) const CONTROLLER_CACHE_JOURNAL: &str = aos_sandbox_protocol::cache_state::fixed_journals::CACHE_BOOTSTRAP_BASENAME_V1;
pub(super) const SOURCE_KEY_PREFIX: &[u8] = aos_sandbox_protocol::cache_state::replay_evidence::SOURCE_KEY_PREFIX;
pub(super) const AUTHORITY_KEY_PREFIX: &[u8] = aos_sandbox_protocol::cache_state::replay_evidence::AUTHORITY_KEY_PREFIX;
const MAXIMUM_SOURCE_PARTITIONS: usize = aos_sandbox_protocol::cache_state::fixed_journals::CACHE_MAXIMUM_BOOTSTRAP_PARTITIONS_V1;
const BUNDLE_MAGIC: &[u8; 8] = aos_sandbox_protocol::cache_state::replay_evidence::BUNDLE_MAGIC;
const BUNDLE_DOMAIN: &[u8] = aos_sandbox_protocol::cache_state::replay_evidence::BUNDLE_DOMAIN;
const MAXIMUM_BUNDLE_BYTES: usize = aos_sandbox_protocol::cache_state::replay_evidence::MAXIMUM_BUNDLE_BYTES;

mod import_geometry;
mod import;
#[cfg(target_os = "linux")]
pub(crate) use import::CacheSelectedBootstrapImportV1;
pub(crate) use import_geometry::CacheBootstrapImportGeometryV1;

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


#[cfg(target_os = "linux")]
/// Retains exact existing source geometry without creating another replay.
pub(in crate::cache_residency) struct OriginalQ04CacheSourceShapeV1 {
    journal: crate::journal::JournalShape,
    names: crate::journal::ProtectedJournalNamesV1,
    sequence: u64,
    manifest_bytes: usize,
    manifest_cells: usize,
}

#[cfg(target_os = "linux")]
impl OriginalQ04CacheSourceShapeV1 {
    /// Compares the complete original fixed extent, capacity and native names.
    pub(in crate::cache_residency) fn same_original(&self, other: &Self) -> bool {
        self.names == other.names && self.sequence == other.sequence
            && self.manifest_bytes == other.manifest_bytes
            && self.manifest_cells == other.manifest_cells
            && self.journal.retained_bytes == other.journal.retained_bytes
            && self.journal.cells == other.journal.cells
            && self.journal.native_bytes == other.journal.native_bytes
            && self.journal.maximum_transaction_bytes == other.journal.maximum_transaction_bytes
            && self.journal.maximum_record_bytes == other.journal.maximum_record_bytes
    }
}

// This closed observation seam lends no raw Journal. The actual initializer
// retains this same owner while the new J-paid Cache Held audit runs.
#[cfg(target_os = "linux")]
impl CacheReplayControllerBootstrapOwnerV1 {
    pub(in crate::cache_residency) fn create_storage_writer_shape_v1(
        &self,
        original: &mut crate::journal::CreateStorageWriterPositionOriginalV1,
    ) -> Result<crate::journal::CacheHeldWriterShapeV1, JournalError> {
        self.journal.capture_cache_held_shape_v1(original,
            super::InitializerJournal::Source, self.owner_uid)
    }

    pub(in crate::cache_residency) fn observe_create_storage_position_v1(
        &mut self,
        original: &mut crate::journal::CreateStorageWriterPositionOriginalV1,
        expected: Option<&crate::journal::CacheHeldWriterShapeV1>,
    ) -> Result<(), CacheReplayControllerBootstrapErrorV1> {
        original.capture_cache_once(&self.journal, super::InitializerJournal::Source, self.owner_uid);
        original.position()?;
        if let Some(expected) = expected { expected.require_observed(&self.journal, original)?; }
        require_original_source_records(&mut self.journal, &self.records)
    }

    pub(in crate::cache_residency) fn create_storage_require_shape_v1(
        &self,
        expected: &crate::journal::CacheHeldWriterShapeV1,
    ) -> Result<(), JournalError> {
        expected.require(&self.journal)
    }

    pub(in crate::cache_residency) fn prepare_create_storage_readback_v1(
        &self,
        expected: &crate::journal::CacheHeldWriterShapeV1,
        destination: &mut crate::journal::ReadOnlyJournalOpenOriginalsV1,
        receiving: &mut super::CacheHeldReadonlyContextV1<'_, '_, '_>,
    ) -> Result<(), JournalError> {
        expected.require(&self.journal)?;
        destination.prepare_captured_cache_once(
            Path::new(CONTROLLER_CACHE_ROOT), CONTROLLER_CACHE_JOURNAL,
            self.journal.configured_limits(), self.owner_uid,
            expected.coordinates.names.directory(), receiving,
        );
        if destination.failure().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        if destination.captured_extent() != Some(&expected.extent) {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        expected.require(&self.journal)
    }

    pub(in crate::cache_residency) fn require_create_storage_readback_v1(
        &self,
        expected: &crate::journal::CacheHeldWriterShapeV1,
        readback: &mut crate::journal::ReadOnlyProtectedJournal,
    ) -> Result<(), JournalError> {
        self.journal.require_cache_held_readback_v1(expected, readback)
    }

    pub(in crate::cache_residency) fn create_storage_fixed_readback_demand_v1<T>()
        -> Result<aos_sandbox_core::ResourceVector, JournalError>
    {
        let descriptors = (Path::new(CONTROLLER_CACHE_ROOT).components().count() + 1) * 2;
        crate::journal::ReadOnlyJournalOpenOriginalsV1::fixed_preparation_demand_v1::<T>(
            descriptors as u16, (CONTROLLER_CACHE_ROOT.len() + CONTROLLER_CACHE_JOURNAL.len()) as u16,
        )
    }

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
        import::import_ordinary(owner_uid, bundle)
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


    /// Captures passive geometry of the same already-open validated originals.
    ///
    /// It neither replays the source file nor clones retained manifest bytes.
    ///
    /// # Errors
    /// Refuses changed native names, extents, records, capacities or overflow.
    #[cfg(target_os = "linux")]
    pub(in crate::cache_residency) fn capture_original_q04_shape(
        &mut self,
    ) -> Result<OriginalQ04CacheSourceShapeV1, CacheReplayControllerBootstrapErrorV1> {
        self.recheck_existing()?;
        let original = self.original_q04_geometry()?;
        self.recheck_existing()?;
        let after = self.original_q04_geometry()?;
        if !original.same_original(&after) {
            return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
        }
        Ok(original)
    }

    #[cfg(target_os = "linux")]
    fn original_q04_geometry(
        &self,
    ) -> Result<OriginalQ04CacheSourceShapeV1, CacheReplayControllerBootstrapErrorV1> {
        let journal = self.journal.first_global_allocation_shape_v1()?;
        let names = self.journal.protected_writer_physical_names_v1()?;
        let sequence = self.journal.snapshot_sequence();
        let manifest_bytes = original_manifest_capacity(self.records.values().map(Vec::capacity))?;
        let manifest_cells = self.records.len();
        Ok(OriginalQ04CacheSourceShapeV1 {
            journal, names, sequence, manifest_bytes, manifest_cells,
        })
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
        decode_genesis_manifest(bytes, CacheRecoveryLimitsV1::default())
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


#[cfg(target_os = "linux")]
fn original_manifest_capacity(
    capacities: impl IntoIterator<Item = usize>,
) -> Result<usize, CacheReplayControllerBootstrapErrorV1> {
    capacities.into_iter().try_fold(0_usize, |total, capacity| {
        total.checked_add(capacity).ok_or(CacheReplayControllerBootstrapErrorV1::InvalidSource)
    })
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
    aos_sandbox_protocol::cache_state::replay_evidence::validate_source_record(key, bytes, limits)
        .map_err(map_bootstrap_history_data_error_v1)
}

fn validate_source_evidence(
    key: &[u8],
    evidence: &CacheResidencyReplayPartitionEvidenceV1,
    limits: CacheRecoveryLimitsV1,
) -> Result<ObjectDigest, CacheReplayControllerBootstrapErrorV1> {
    aos_sandbox_protocol::cache_state::replay_evidence::validate_source_evidence(key, evidence, limits)
        .map_err(map_bootstrap_history_data_error_v1)
}

fn source_key(partition: ObjectDigest) -> Vec<u8> {
    aos_sandbox_protocol::cache_state::replay_evidence::source_key(partition)
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
    project_quotas: Vec<ProjectCacheQuotaV1>,
    valid_until: u64,
) -> Result<Vec<u8>, CacheReplayControllerBootstrapErrorV1> {
    aos_sandbox_protocol::cache_state::replay_evidence::encode_cache_replay_genesis_manifest_v1(partition, node_quota, project_quotas, valid_until)
        .map_err(map_bootstrap_history_data_error_v1)
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
    aos_sandbox_protocol::cache_state::replay_evidence::encode_cache_replay_controller_bundle_v1(manifests)
        .map_err(map_bootstrap_history_data_error_v1)
}

fn decode_controller_bundle(
    bytes: &[u8],
) -> Result<BTreeMap<ObjectDigest, Vec<u8>>, CacheReplayControllerBootstrapErrorV1> {
    aos_sandbox_protocol::cache_state::replay_evidence::decode_controller_bundle(bytes)
        .map_err(map_bootstrap_history_data_error_v1)
}

fn decode_genesis_manifest(
    bytes: &[u8],
    limits: CacheRecoveryLimitsV1,
) -> Result<CacheResidencyReplayPartitionEvidenceV1, CacheResidencyProtectedJournalErrorV1> {
    aos_sandbox_protocol::cache_state::replay_evidence::decode_genesis_manifest(bytes, limits)
        .map_err(|_| crate::protected_domain_journal::ProtectedDomainJournalErrorV1::NonCanonicalRecord)
}

pub(super) fn replay_authority_key(partition: ObjectDigest) -> Vec<u8> {
    aos_sandbox_protocol::cache_state::replay_evidence::replay_authority_key(partition)
}

pub(in crate::cache_residency) fn controller_cache_journal_limits() -> JournalLimits {
    aos_sandbox_protocol::cache_state::fixed_journals::CacheJournalRecipeRoleV1::Bootstrap.limits_v1()
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

    pub(super) fn fixture() -> (tempfile::TempDir, Journal, BTreeMap<ObjectDigest, Vec<u8>>) {
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


#[cfg(all(test, target_os = "linux"))]
mod q04_source_geometry_tests {
    use std::os::unix::fs::MetadataExt as _;

    use super::*;

    #[test]
    fn exact_actual_capacities_and_native_append_cannot_keep_the_old_shape() {
        let (directory, journal, records) = super::original_source_tests::fixture();
        let owner_uid = std::fs::metadata(directory.path()).unwrap().uid();
        let mut original = CacheReplayControllerBootstrapOwnerV1 { journal, records, owner_uid };
        let before = original.original_q04_geometry().unwrap();
        let expected_bytes = original.records.values().map(Vec::capacity).sum::<usize>();

        assert_eq!(before.manifest_bytes, expected_bytes);
        assert!(before.same_original(&original.original_q04_geometry().unwrap()));

        original.records.values_mut().next().unwrap().reserve_exact(1024);
        let larger = original.original_q04_geometry().unwrap();
        assert!(!before.same_original(&larger));

        let transaction = JournalTransaction::new([3; 16], vec![JournalRecord::put(
            RecordNamespace::DesiredState, b"extra".to_vec(), vec![1],
        )]).unwrap();
        original.journal.commit(&transaction).unwrap();
        assert!(!larger.same_original(&original.original_q04_geometry().unwrap()));
    }

    #[test]
    fn resident_capacity_sum_rejects_overflow_without_allocating_that_extent() {
        assert_eq!(original_manifest_capacity([usize::MAX, 0]).unwrap(), usize::MAX);
        assert!(matches!(original_manifest_capacity([usize::MAX, 1]),
            Err(CacheReplayControllerBootstrapErrorV1::InvalidSource)));
    }
}


fn map_bootstrap_history_data_error_v1(error: aos_sandbox_protocol::cache_state::replay_evidence::CacheBootstrapHistoryDataErrorV1) -> CacheReplayControllerBootstrapErrorV1 {
    match error {
        aos_sandbox_protocol::cache_state::replay_evidence::CacheBootstrapHistoryDataErrorV1::InvalidSource => CacheReplayControllerBootstrapErrorV1::InvalidSource,
        aos_sandbox_protocol::cache_state::replay_evidence::CacheBootstrapHistoryDataErrorV1::Manifest(_) => CacheReplayControllerBootstrapErrorV1::Target(crate::protected_domain_journal::ProtectedDomainJournalErrorV1::NonCanonicalRecord),
    }
}
