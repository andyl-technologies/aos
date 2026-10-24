//! Shares complete historical Cache replay manifests and Bootstrap framing.
//!
//! Every typed checkpoint, Genesis constraint, partition/scope join, canonical
//! reencoding and bounded bundle iteration uses the existing single engine.
//! These historical models grant no live capability or financial purpose.
//! Native callers retain current-record verification and native bookends.
//!
//! ```text
//! manifest = AOSCRM01 | complete header555 | key | typed checkpoint | prior
//! bundle   = AOSCRB01 | version:u16=1 | count:u16 | reserved:4 |
//!            repeated(length:u32 | manifest) | SHA256(domain || preceding)
//! ```

use super::authority_record::CacheAuthorityPurposeV1;
use super::durable_format::{CacheHistoryFloorV1, encode_floor};
use super::recovery::{
    CacheGlobalRecoveryStateV1, CacheRecoveryInventoryDataV1, CacheRecoveryLimitsV1,
    CacheTypedCheckpointV1, decode_typed_checkpoint, encode_typed_checkpoint,
    genesis_checkpoint_project_count,
};
use super::replay_envelope::{
    BorrowedCacheReplayManifestDataV1, CACHE_MANIFEST_FIXED_BYTES, CACHE_MANIFEST_MAGIC,
    CacheReplayEnvelopeDataErrorV1, CacheReplayPartitionEvidenceDataV1,
    borrow_cache_replay_manifest, encode_partition_descriptor,
};
use super::{NodeCacheQuotaV1, PhysicalPartitionId, ProjectCacheQuotaV1};
use aos_sandbox_model::{ObjectDigest, bounded_codec::BoundedReader};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

/// Names the original Controller immutable-bootstrap row prefix.
pub const SOURCE_KEY_PREFIX: &[u8] = b"\0aos-cache-controller-bootstrap-v1\0";
/// Names the original replay-authority row prefix.
pub const AUTHORITY_KEY_PREFIX: &[u8] = b"\0aos-cache-replay-authority-v1\0";
const MAXIMUM_SOURCE_PARTITIONS: usize =
    super::fixed_journals::CACHE_MAXIMUM_BOOTSTRAP_PARTITIONS_V1;
/// Identifies the existing Bootstrap bundle magic.
pub const BUNDLE_MAGIC: &[u8; 8] = b"AOSCRB01";
/// Separates the existing Bootstrap bundle checksum domain.
pub const BUNDLE_DOMAIN: &[u8] = b"aos.sandbox.cache.controller-bundle.v1\0";
/// Bounds the existing complete Bootstrap bundle representation.
pub const MAXIMUM_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
type BundleReader<'bytes> = BoundedReader<'bytes, CacheBootstrapHistoryDataErrorV1>;

/// Classifies historical Bootstrap DATA without a native error or capability.
#[derive(Debug, thiserror::Error)]
pub enum CacheBootstrapHistoryDataErrorV1 {
    /// Refuses malformed, unordered, incomplete or divergent Bootstrap input.
    #[error("Cache Bootstrap history DATA is invalid")]
    InvalidSource,
    /// Preserves the existing manifest-encoding failure frontier separately.
    #[error(transparent)]
    Manifest(#[from] CacheReplayEnvelopeDataErrorV1),
}

/// Decodes and canonically reencodes the same complete replay manifest.
///
/// # Errors
/// Refuses invalid envelope fields, malformed current/prior typed checkpoints or noncanonical reencoding.
pub fn decode_cache_replay_manifest(
    bytes: &[u8],
    limits: CacheRecoveryLimitsV1,
) -> Result<CacheReplayPartitionEvidenceDataV1, CacheReplayEnvelopeDataErrorV1> {
    let borrowed = borrow_cache_replay_manifest(bytes, limits.maximum_payload_bytes)?;
    let BorrowedCacheReplayManifestDataV1 {
        partition,
        purpose,
        scope,
        floor,
        record_key,
        typed_checkpoint,
        prior_typed_checkpoint,
    } = borrowed;
    let record_key = record_key.to_vec();
    let typed_checkpoint = typed_checkpoint.to_vec();
    let prior_typed_checkpoint = prior_typed_checkpoint.map(<[u8]>::to_vec);
    decode_typed_checkpoint(partition, &typed_checkpoint, limits)
        .map_err(|_| CacheReplayEnvelopeDataErrorV1)?;
    if let Some(prior) = prior_typed_checkpoint.as_deref() {
        decode_typed_checkpoint(partition, prior, limits)
            .map_err(|_| CacheReplayEnvelopeDataErrorV1)?;
    }
    let evidence = CacheReplayPartitionEvidenceDataV1 {
        partition,
        purpose,
        scope,
        record_key,
        typed_checkpoint,
        prior_typed_checkpoint,
        floor,
    };
    if encode_cache_replay_manifest(&evidence, limits)?.as_slice() != bytes {
        return Err(CacheReplayEnvelopeDataErrorV1);
    }
    Ok(evidence)
}

/// Encodes complete historical replay evidence using the existing manifest format.
///
/// # Errors
/// Refuses invalid key/payload widths, scope partition mismatch, malformed typed checkpoints or overflow.
pub fn encode_cache_replay_manifest(
    evidence: &CacheReplayPartitionEvidenceDataV1,
    limits: CacheRecoveryLimitsV1,
) -> Result<Vec<u8>, CacheReplayEnvelopeDataErrorV1> {
    let record_key_bytes =
        u16::try_from(evidence.record_key.len()).map_err(|_| CacheReplayEnvelopeDataErrorV1)?;
    let checkpoint_bytes = u32::try_from(evidence.typed_checkpoint.len())
        .map_err(|_| CacheReplayEnvelopeDataErrorV1)?;
    let prior = evidence
        .prior_typed_checkpoint
        .as_deref()
        .unwrap_or_default();
    let prior_bytes = u32::try_from(prior.len()).map_err(|_| CacheReplayEnvelopeDataErrorV1)?;
    let total_bytes = CACHE_MANIFEST_FIXED_BYTES
        .checked_add(evidence.record_key.len())
        .and_then(|length| length.checked_add(evidence.typed_checkpoint.len()))
        .and_then(|length| length.checked_add(prior.len()))
        .ok_or(CacheReplayEnvelopeDataErrorV1)?;
    if evidence.record_key.is_empty()
        || evidence.record_key.len() > 1024
        || evidence.typed_checkpoint.is_empty()
        || evidence.typed_checkpoint.len() > limits.maximum_payload_bytes
        || prior.len() > limits.maximum_payload_bytes
        || evidence
            .prior_typed_checkpoint
            .as_ref()
            .is_some_and(Vec::is_empty)
        || evidence.scope.partition() != evidence.partition.digest()
    {
        return Err(CacheReplayEnvelopeDataErrorV1);
    }
    decode_typed_checkpoint(evidence.partition, &evidence.typed_checkpoint, limits)
        .map_err(|_| CacheReplayEnvelopeDataErrorV1)?;
    if !prior.is_empty() {
        decode_typed_checkpoint(evidence.partition, prior, limits)
            .map_err(|_| CacheReplayEnvelopeDataErrorV1)?;
    }

    let mut bytes = vec![0_u8; total_bytes];
    bytes[..8].copy_from_slice(CACHE_MANIFEST_MAGIC);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..257].copy_from_slice(&encode_partition_descriptor(evidence.partition));
    bytes[257] = evidence.purpose as u8;
    bytes[265..297].copy_from_slice(evidence.scope.subject().as_bytes());
    bytes[297..313].copy_from_slice(&evidence.scope.operation());
    bytes[313..345].copy_from_slice(evidence.scope.plan().as_bytes());
    bytes[345..377].copy_from_slice(evidence.scope.root_custody().as_bytes());
    bytes[377..385].copy_from_slice(&evidence.scope.generation().to_be_bytes());
    bytes[385..393].copy_from_slice(&evidence.scope.valid_until().to_be_bytes());
    bytes[393..545].copy_from_slice(
        &encode_floor(&evidence.floor).map_err(|_| CacheReplayEnvelopeDataErrorV1)?,
    );
    bytes[545..547].copy_from_slice(&record_key_bytes.to_be_bytes());
    bytes[547..551].copy_from_slice(&checkpoint_bytes.to_be_bytes());
    bytes[551..555].copy_from_slice(&prior_bytes.to_be_bytes());
    let record_key_end = CACHE_MANIFEST_FIXED_BYTES + evidence.record_key.len();
    let checkpoint_end = record_key_end + evidence.typed_checkpoint.len();
    bytes[CACHE_MANIFEST_FIXED_BYTES..record_key_end].copy_from_slice(&evidence.record_key);
    bytes[record_key_end..checkpoint_end].copy_from_slice(&evidence.typed_checkpoint);
    bytes[checkpoint_end..].copy_from_slice(prior);
    Ok(bytes)
}

/// Validates the same closed Genesis checkpoint and floor shape.
///
/// # Errors
/// Refuses malformed checkpoints, non-Genesis sequence/floor or any nonempty prior state family.
pub fn validate_genesis_checkpoint(
    partition: PhysicalPartitionId,
    typed_checkpoint: &[u8],
    floor: CacheHistoryFloorV1,
    limits: CacheRecoveryLimitsV1,
) -> Result<(), CacheReplayEnvelopeDataErrorV1> {
    let checkpoint = decode_typed_checkpoint(partition, typed_checkpoint, limits)
        .map_err(|_| CacheReplayEnvelopeDataErrorV1)?;
    if checkpoint.checkpoint.sequence != 1
        || floor.first_retained_sequence != 2
        || floor.predecessor.as_bytes() != &[0; 32]
        || !checkpoint.baselines.is_empty()
        || !checkpoint.family_heads.is_empty()
        || !checkpoint.global.watermarks.is_empty()
        || !checkpoint.global.idempotency.is_empty()
        || checkpoint.global.pin_floor.is_some()
        || checkpoint.global.idempotency_floor.is_some()
        || !checkpoint.global.handoffs.is_empty()
        || !checkpoint.global.lookups.is_empty()
        || checkpoint.global.poison.is_some()
    {
        return Err(CacheReplayEnvelopeDataErrorV1.into());
    }
    Ok(())
}

/// Borrows the same closed Genesis framing before typed allocations.
///
/// # Errors
/// Refuses wrong Replay purpose, prior checkpoint, floor, authority key or closed Genesis shape.
pub fn genesis_manifest_project_count(
    bytes: &[u8],
    limits: CacheRecoveryLimitsV1,
) -> Result<usize, CacheReplayEnvelopeDataErrorV1> {
    let manifest = borrow_cache_replay_manifest(bytes, limits.maximum_payload_bytes)?;
    if manifest.purpose != CacheAuthorityPurposeV1::Replay
        || manifest.prior_typed_checkpoint.is_some()
        || manifest.floor.first_retained_sequence != 2
        || manifest.floor.predecessor.as_bytes() != &[0; 32]
        || manifest.record_key.strip_prefix(AUTHORITY_KEY_PREFIX)
            != Some(&manifest.partition.digest().as_bytes()[..])
    {
        return Err(CacheReplayEnvelopeDataErrorV1);
    }
    genesis_checkpoint_project_count(manifest.partition, manifest.typed_checkpoint, limits)
        .map_err(|_| CacheReplayEnvelopeDataErrorV1)
}

/// Validates one complete historical Controller Bootstrap row.
///
/// # Errors
/// Refuses a foreign key, malformed Genesis manifest or divergent scope/partition association.
pub fn validate_source_record(
    key: &[u8],
    bytes: &[u8],
    limits: CacheRecoveryLimitsV1,
) -> Result<ObjectDigest, CacheBootstrapHistoryDataErrorV1> {
    if !key.starts_with(SOURCE_KEY_PREFIX) || key.len() != SOURCE_KEY_PREFIX.len() + 32 {
        return Err(CacheBootstrapHistoryDataErrorV1::InvalidSource);
    }
    let evidence = decode_genesis_manifest(bytes, limits)
        .map_err(|_| CacheBootstrapHistoryDataErrorV1::InvalidSource)?;
    validate_source_evidence(key, &evidence, limits)
}

/// Compares the same complete Genesis evidence with its original lookup key.
///
/// # Errors
/// Refuses wrong purpose, prior state, key, floor, checkpoint or derived scope.
pub fn validate_source_evidence(
    key: &[u8],
    evidence: &CacheReplayPartitionEvidenceDataV1,
    limits: CacheRecoveryLimitsV1,
) -> Result<ObjectDigest, CacheBootstrapHistoryDataErrorV1> {
    let partition = evidence.partition.digest();
    if evidence.purpose != CacheAuthorityPurposeV1::Replay
        || evidence.prior_typed_checkpoint.is_some()
        || key != source_key(partition)
        || evidence.record_key != replay_authority_key(partition)
    {
        return Err(CacheBootstrapHistoryDataErrorV1::InvalidSource);
    }
    validate_genesis_checkpoint(
        evidence.partition,
        &evidence.typed_checkpoint,
        evidence.floor,
        limits,
    )
    .map_err(|_| CacheBootstrapHistoryDataErrorV1::InvalidSource)?;
    let derived = CacheRecoveryInventoryDataV1::replay_authority_scope(
        evidence.partition,
        &evidence.typed_checkpoint,
        None,
        evidence.floor,
        evidence.scope.valid_until(),
        limits,
    )
    .map_err(|_| CacheBootstrapHistoryDataErrorV1::InvalidSource)?;
    if derived != evidence.scope {
        return Err(CacheBootstrapHistoryDataErrorV1::InvalidSource);
    }
    Ok(partition)
}

/// Constructs the existing immutable Bootstrap lookup key as comparison DATA.
pub fn source_key(partition: ObjectDigest) -> Vec<u8> {
    let mut key = Vec::with_capacity(SOURCE_KEY_PREFIX.len() + 32);
    key.extend_from_slice(SOURCE_KEY_PREFIX);
    key.extend_from_slice(partition.as_bytes());
    key
}

/// Encodes the existing complete quota-derived Genesis checkpoint manifest.
///
/// # Errors
/// Refuses invalid quotas/validity, inconsistent typed state or an over-bound manifest.
pub fn encode_cache_replay_genesis_manifest_v1(
    partition: PhysicalPartitionId,
    node_quota: NodeCacheQuotaV1,
    mut project_quotas: Vec<ProjectCacheQuotaV1>,
    valid_until: u64,
) -> Result<Vec<u8>, CacheBootstrapHistoryDataErrorV1> {
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
    .map_err(|_| CacheBootstrapHistoryDataErrorV1::InvalidSource)?;
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
    .map_err(|_| CacheBootstrapHistoryDataErrorV1::InvalidSource)?;
    let typed_checkpoint = encode_typed_checkpoint(&typed, partition, limits)
        .map_err(|_| CacheBootstrapHistoryDataErrorV1::InvalidSource)?;
    let floor = CacheHistoryFloorV1::new(
        2,
        typed.checkpoint.digest,
        ObjectDigest::from_bytes([0; 32]),
        history_head,
    )
    .map_err(|_| CacheBootstrapHistoryDataErrorV1::InvalidSource)?;
    let scope = CacheRecoveryInventoryDataV1::replay_authority_scope(
        partition,
        &typed_checkpoint,
        None,
        floor,
        valid_until,
        limits,
    )
    .map_err(|_| CacheBootstrapHistoryDataErrorV1::InvalidSource)?;
    let evidence = CacheReplayPartitionEvidenceDataV1 {
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

/// Encodes the same sorted complete Bootstrap manifest bundle.
///
/// # Errors
/// Refuses malformed, duplicate, empty, unordered or over-bound partition manifests.
pub fn encode_cache_replay_controller_bundle_v1(
    manifests: impl IntoIterator<Item = Vec<u8>>,
) -> Result<Vec<u8>, CacheBootstrapHistoryDataErrorV1> {
    let mut records = BTreeMap::new();
    let mut bounded_bytes = 48_usize;
    let limits = CacheRecoveryLimitsV1::default();
    for manifest in manifests {
        bounded_bytes = bounded_bytes
            .checked_add(4)
            .and_then(|size| size.checked_add(manifest.len()))
            .filter(|size| *size <= MAXIMUM_BUNDLE_BYTES)
            .ok_or(CacheBootstrapHistoryDataErrorV1::InvalidSource)?;
        let evidence = decode_genesis_manifest(&manifest, limits)
            .map_err(|_| CacheBootstrapHistoryDataErrorV1::InvalidSource)?;
        let partition = evidence.partition.digest();
        validate_source_evidence(&source_key(partition), &evidence, limits)?;
        if records.insert(partition, manifest).is_some()
            || records.len() > MAXIMUM_SOURCE_PARTITIONS
        {
            return Err(CacheBootstrapHistoryDataErrorV1::InvalidSource);
        }
    }
    if records.is_empty() {
        return Err(CacheBootstrapHistoryDataErrorV1::InvalidSource);
    }

    let count = u16::try_from(records.len())
        .map_err(|_| CacheBootstrapHistoryDataErrorV1::InvalidSource)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(BUNDLE_MAGIC);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(&[0; 4]);
    for manifest in records.values() {
        let length = u32::try_from(manifest.len())
            .map_err(|_| CacheBootstrapHistoryDataErrorV1::InvalidSource)?;
        if bytes
            .len()
            .checked_add(4)
            .and_then(|size| size.checked_add(manifest.len()))
            .and_then(|size| size.checked_add(32))
            .is_none_or(|size| size > MAXIMUM_BUNDLE_BYTES)
        {
            return Err(CacheBootstrapHistoryDataErrorV1::InvalidSource);
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

/// Decodes and validates every manifest in the same bounded Bootstrap bundle.
///
/// # Errors
/// Refuses malformed framing/checksum, malformed Genesis manifests, duplicate or unordered partitions.
pub fn decode_controller_bundle(
    bytes: &[u8],
) -> Result<BTreeMap<ObjectDigest, Vec<u8>>, CacheBootstrapHistoryDataErrorV1> {
    let view = ControllerBundleViewV1::new(bytes)?;
    let mut records = BTreeMap::new();
    let mut previous = None;
    let limits = CacheRecoveryLimitsV1::default();
    for manifest in view.manifests() {
        let manifest = manifest?;
        let evidence = decode_genesis_manifest(manifest, limits)
            .map_err(|_| CacheBootstrapHistoryDataErrorV1::InvalidSource)?;
        let partition = evidence.partition.digest();
        validate_source_evidence(&source_key(partition), &evidence, limits)?;
        if previous.is_some_and(|previous| partition <= previous)
            || records.insert(partition, manifest.to_vec()).is_some()
        {
            return Err(CacheBootstrapHistoryDataErrorV1::InvalidSource);
        }
        previous = Some(partition);
    }
    Ok(records)
}

/// Validates closed Genesis framing before the same complete typed decoder.
///
/// # Errors
/// Refuses an invalid closed header, over-bound fields or malformed typed checkpoint.
pub fn decode_genesis_manifest(
    bytes: &[u8],
    limits: CacheRecoveryLimitsV1,
) -> Result<CacheReplayPartitionEvidenceDataV1, CacheReplayEnvelopeDataErrorV1> {
    // The bootstrap format already requires this closed Genesis shape. Check
    // it before the general decoder reserves any advertised typed carriers.
    genesis_manifest_project_count(bytes, limits)?;
    decode_cache_replay_manifest(bytes, limits)
}

/// Constructs the existing Replay-authority lookup key as comparison DATA.
pub fn replay_authority_key(partition: ObjectDigest) -> Vec<u8> {
    let mut key = Vec::with_capacity(AUTHORITY_KEY_PREFIX.len() + 32);
    key.extend_from_slice(AUTHORITY_KEY_PREFIX);
    key.extend_from_slice(partition.as_bytes());
    key
}

/// Borrows the complete checksum-verified framing without issuing trust.
pub struct ControllerBundleViewV1<'bytes> {
    manifests: &'bytes [u8],
    count: usize,
}

impl<'bytes> ControllerBundleViewV1<'bytes> {
    /// Returns the actual bounded framing's manifest count.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Checks the existing bounded bundle header and complete checksum.
    ///
    /// # Errors
    /// Refuses bad version, reserved bytes, count, extent or checksum.
    pub fn new(bytes: &'bytes [u8]) -> Result<Self, CacheBootstrapHistoryDataErrorV1> {
        if bytes.len() < 48 || bytes.len() > MAXIMUM_BUNDLE_BYTES {
            return Err(CacheBootstrapHistoryDataErrorV1::InvalidSource);
        }
        let footer = bytes.len() - 32;
        let digest = Sha256::new()
            .chain_update(BUNDLE_DOMAIN)
            .chain_update(&bytes[..footer])
            .finalize();
        if bytes[footer..] != digest[..] {
            return Err(CacheBootstrapHistoryDataErrorV1::InvalidSource);
        }
        let mut reader = BundleReader::new(&bytes[..footer], |_| {
            CacheBootstrapHistoryDataErrorV1::InvalidSource
        });
        if reader.bytes(8)? != BUNDLE_MAGIC || reader.u16()? != 1 {
            return Err(CacheBootstrapHistoryDataErrorV1::InvalidSource);
        }
        let count = usize::from(reader.u16()?);
        reader.zeros(4)?;
        if count == 0 || count > MAXIMUM_SOURCE_PARTITIONS {
            return Err(CacheBootstrapHistoryDataErrorV1::InvalidSource);
        }
        Ok(Self {
            manifests: reader.remaining_bytes(),
            count,
        })
    }

    /// Borrows each length-delimited manifest in its original encoded order.
    pub fn manifests(self) -> BundleManifestIterV1<'bytes> {
        BundleManifestIterV1 {
            reader: BundleReader::new(self.manifests, |_| {
                CacheBootstrapHistoryDataErrorV1::InvalidSource
            }),
            remaining: self.count,
            failed: false,
        }
    }
}

/// Iterates the same bounded manifest slices, retaining no native authority.
pub struct BundleManifestIterV1<'bytes> {
    reader: BundleReader<'bytes>,
    remaining: usize,
    failed: bool,
}

impl<'bytes> Iterator for BundleManifestIterV1<'bytes> {
    type Item = Result<&'bytes [u8], CacheBootstrapHistoryDataErrorV1>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.remaining == 0 {
            return None;
        }
        let result = (|| {
            let length = usize::try_from(self.reader.u32()?)
                .map_err(|_| CacheBootstrapHistoryDataErrorV1::InvalidSource)?;
            let bytes = self.reader.bytes(length)?;
            self.remaining -= 1;
            if self.remaining == 0 && !self.reader.is_empty() {
                return Err(CacheBootstrapHistoryDataErrorV1::InvalidSource);
            }
            Ok(bytes)
        })();
        self.failed = result.is_err();
        Some(result)
    }
}

/// Names the complete historical replay-manifest namespace prefix.
pub const CACHE_REPLAY_MANIFEST_KEY_PREFIX_V1: &[u8] = b"\0aos-cache-replay-manifest-v1\0";
/// Bounds the existing complete replay-manifest inventory.
pub const CACHE_MAXIMUM_REPLAY_MANIFESTS_V1: usize = 4_096;

/// Commits the existing fixed Cache owner scope as nonauthorizing DATA.
#[must_use]
pub fn cache_fixed_owner_scope_data_v1() -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.cache-residency.fixed-owner.v1\0")
            .chain_update(super::fixed_journals::CACHE_JOURNAL_DIRECTORY_V1.as_bytes())
            .finalize()
            .into(),
    )
}

/// Compares the exact historical session scope and published checkpoint set.
///
/// This is the existing Native session predicate as comparison DATA. The
/// caller still owns its actual authority record, protected prefix and current
/// native session; this function cannot construct any of those owners.
///
/// # Errors
/// Returns `AnchorMismatch` for a foreign partition, purpose, scope or checkpoint.
pub fn validate_partition_session_history_data_v1(
    evidence: &CacheReplayPartitionEvidenceDataV1,
    partition: PhysicalPartitionId,
    session_scope: super::authority_record::CacheAuthorityScopeV1,
    published_checkpoints: &[Vec<u8>],
) -> Result<(), super::recovery::RecoveryError> {
    if evidence.partition != partition
        || evidence.purpose != CacheAuthorityPurposeV1::Replay
        || evidence.scope != session_scope
        || (!published_checkpoints.is_empty()
            && (!published_checkpoints
                .iter()
                .any(|checkpoint| checkpoint == &evidence.typed_checkpoint)
                || published_checkpoints.iter().any(|checkpoint| {
                    checkpoint != &evidence.typed_checkpoint
                        && evidence.prior_typed_checkpoint.as_ref() != Some(checkpoint)
                })))
    {
        return Err(super::recovery::RecoveryError::AnchorMismatch);
    }
    Ok(())
}
