//! Dormant protected-journal ownership for cache residency.
//!
//! The adapter commits only canonical reducer output. It does not open cache
//! roots, allocate storage, unlink objects, or make a reader-visible catalog
//! change. Those actions require the postcommit capabilities minted here.

use aos_sandbox_core::{
    CacheDomainId, ObjectDescriptor, ObjectDigest, ProjectId,
    model::{CacheDomain, CacheDomainKind},
};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use crate::journal::{Journal, JournalError, RecordNamespace};
use crate::lifecycle::protected_journal_adapter::{
    AppliedDomainTransactionV1, DomainCommitOutcomeV1, DomainOutcomeUnknownV1,
    DomainPostcommitCapabilityV1, DomainRecoveryV1, DomainRetainedRecoveryV1,
    PreparedDomainTransactionV1, ProtectedDomainEnvelopeV1, ProtectedDomainJournalErrorV1,
    ProtectedDomainJournalV1, ProtectedDomainKeyV1, ProtectedDomainProjectionV1,
    ProtectedDomainReplayPhaseV1, ProtectedDomainSchemaV1, ProtectedDomainSnapshotV1,
    ProtectedRecordRoleV1, ProtectedReducerPhaseV1, ReplayedDomainPostcommitV1,
    ValidatedDomainPostcommitV1, decode_reducer_payload_with_validator,
    encode_reducer_payload_with_validator,
};

use super::{
    CacheAtomicObjectPayloadV1, CacheAuthorityOwner, CacheAuthorityPurposeV1,
    CacheAuthorityScopeV1, CacheDurableRecordV1, CacheHistoryFloorV1, CacheNodeIdV1,
    CacheRecordKindV1, CacheRecoveryInventoryV1, CacheRecoveryLimitsV1, CacheTypedCheckpointV1,
    PhysicalPartitionId, ProtectedBackingIdentityV1, RecoveryError, decode_atomic_object_record,
    decode_typed_checkpoint, encode_atomic_object_record, encode_typed_checkpoint,
};
#[cfg(target_os = "linux")]
use super::{CachePinV1, ImmutableAdmissionPlanV1};

mod pin_effect;
mod provisioning;
pub(crate) use provisioning::LOGICAL_PIN_ACQUIRE_LIFETIME_SECONDS;

use pin_effect::{
    CurrentPhysicalPinActionV1, CurrentPhysicalPinEffectV1, current_physical_pin_effect,
};

const PARTITION_DESCRIPTOR_MAGIC: &[u8; 8] = b"AOSCPP01";
const PARTITION_DESCRIPTOR_BYTES: usize = 241;
const EFFECT_OBSERVATION_AUTHORITY_KEY_PREFIX: &[u8] =
    b"\0aos-cache-effect-observation-authority-v1\0";
const EFFECT_OBSERVATION_AUTHORITY_BYTES: usize = 192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CacheEffectObservationV1 {
    transaction_id: [u8; 16],
    transaction_digest: ObjectDigest,
    evidence: ObjectDigest,
    partition: ObjectDigest,
}

fn encode_cache_effect_observation(observation: CacheEffectObservationV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(122);
    bytes.extend_from_slice(b"AOSCRY01");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&observation.transaction_id);
    bytes.extend_from_slice(observation.transaction_digest.as_bytes());
    bytes.extend_from_slice(observation.evidence.as_bytes());
    bytes.extend_from_slice(observation.partition.as_bytes());
    bytes
}

fn decode_cache_effect_observation(
    identity: &[u8],
    bytes: &[u8],
) -> Option<CacheEffectObservationV1> {
    if identity.len() != 16
        || bytes.len() != 122
        || &bytes[..8] != b"AOSCRY01"
        || bytes[8..10] != 1_u16.to_be_bytes()
        || identity != &bytes[10..26]
    {
        return None;
    }
    let observation = CacheEffectObservationV1 {
        transaction_id: bytes[10..26].try_into().ok()?,
        transaction_digest: ObjectDigest::from_bytes(bytes[26..58].try_into().ok()?),
        evidence: ObjectDigest::from_bytes(bytes[58..90].try_into().ok()?),
        partition: ObjectDigest::from_bytes(bytes[90..122].try_into().ok()?),
    };
    if observation.transaction_id == [0; 16]
        || observation.transaction_digest.as_bytes() == &[0; 32]
        || observation.evidence.as_bytes() == &[0; 32]
        || observation.partition.as_bytes() == &[0; 32]
        || encode_cache_effect_observation(observation) != bytes
    {
        return None;
    }
    Some(observation)
}

fn cache_effect_observation_authority_key(transaction_id: [u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(EFFECT_OBSERVATION_AUTHORITY_KEY_PREFIX.len() + 16);
    key.extend_from_slice(EFFECT_OBSERVATION_AUTHORITY_KEY_PREFIX);
    key.extend_from_slice(&transaction_id);
    key
}

fn encode_cache_effect_observation_authority(
    owner_scope: ObjectDigest,
    transaction_id: [u8; 16],
    transaction_digest: ObjectDigest,
    partition: ObjectDigest,
    evidence: ObjectDigest,
) -> Vec<u8> {
    let mut bytes = vec![0_u8; EFFECT_OBSERVATION_AUTHORITY_BYTES];
    bytes[..8].copy_from_slice(b"AOSCOA01");
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..48].copy_from_slice(owner_scope.as_bytes());
    bytes[48..64].copy_from_slice(&transaction_id);
    bytes[64..96].copy_from_slice(transaction_digest.as_bytes());
    bytes[96..128].copy_from_slice(partition.as_bytes());
    bytes[128..160].copy_from_slice(evidence.as_bytes());
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.cache.effect-observation-authority.v1\0")
        .chain_update(&bytes[..160])
        .finalize();
    bytes[160..192].copy_from_slice(&digest);
    bytes
}

/// Selects one closed cache-residency record family.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CacheResidencyProtectedRecordKindV1 {
    /// Stores the exact current capability and isolation-policy authority.
    Authority = 1,
    /// Stores node-global physical accounting.
    GlobalAccounting = 2,
    /// Stores project-attributed accounting under the global total.
    ProjectAccounting = 3,
    /// Stores disclosure-domain accounting under the project total.
    DomainAccounting = 4,
    /// Stores one capacity reservation generation.
    Reservation = 5,
    /// Stores one logical, source, kernel, or backing pin generation.
    Pin = 6,
    /// Stores a trusted scrub observation or quarantine decision.
    Scrub = 7,
    /// Stores a frozen eviction decision or reclamation observation.
    Eviction = 8,
    /// Stores immutable catalog reachability and backing identity.
    Catalog = 9,
    /// Stores a pre-effect admission, scrub, or unlink boundary.
    Effect = 10,
    /// Publishes the exact current cache projection.
    Current = 11,
    /// Publishes a replay join without granting compaction authority.
    Checkpoint = 12,
    /// Suppresses one cold effect after a trusted physical observation.
    EffectObservation = 13,
}

/// Defines the cache-residency protected-journal schema.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CacheResidencyProtectedJournalSchemaV1;

/// Revalidates complete cache history against protected authority on every replay.
trait CacheResidencyReplayAuthorityV1: Send + Sync {
    /// Lists every custodied partition, including a checkpoint-only partition.
    fn partitions(&self) -> Result<Vec<PhysicalPartitionId>, RecoveryError>;

    /// Replays a canonical suffix beneath one exact protected checkpoint/floor anchor.
    fn validate_partition(
        &self,
        partition: PhysicalPartitionId,
        published_checkpoints: &[Vec<u8>],
        records: &[Vec<u8>],
        limits: CacheRecoveryLimitsV1,
    ) -> Result<CacheRecoveryInventoryV1, RecoveryError>;

    /// Authenticates one exact physical observation from protected storage.
    fn effect_observation_is_authentic(
        &self,
        transaction_id: [u8; 16],
        transaction_digest: ObjectDigest,
        partition: ObjectDigest,
        evidence: ObjectDigest,
    ) -> bool;
}

/// Retains a sealed authority callback for full validation on every replay.
#[derive(Clone)]
pub struct CacheResidencyReplayValidatorV1 {
    limits: CacheRecoveryLimitsV1,
    authority: Arc<dyn CacheResidencyReplayAuthorityV1>,
}

impl CacheResidencyReplayValidatorV1 {
    /// Binds replay to one owned protected-authority validator.
    ///
    /// # Errors
    ///
    /// Returns [`CacheResidencyProtectedJournalErrorV1`] for invalid limits.
    fn new(
        authority: Arc<dyn CacheResidencyReplayAuthorityV1>,
        limits: CacheRecoveryLimitsV1,
    ) -> Result<Self, CacheResidencyProtectedJournalErrorV1> {
        let limits = limits
            .validate()
            .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
        Ok(Self { limits, authority })
    }
}

impl std::fmt::Debug for CacheResidencyReplayValidatorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CacheResidencyReplayValidatorV1")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// Owns the exact protected evidence needed to revalidate one cache partition.
#[derive(Clone)]
pub(crate) struct CacheResidencyReplayPartitionEvidenceV1 {
    pub(crate) partition: PhysicalPartitionId,
    pub(crate) purpose: CacheAuthorityPurposeV1,
    pub(crate) scope: CacheAuthorityScopeV1,
    pub(crate) record_key: Vec<u8>,
    pub(crate) typed_checkpoint: Vec<u8>,
    pub(crate) prior_typed_checkpoint: Option<Vec<u8>>,
    pub(crate) floor: CacheHistoryFloorV1,
}

/// Supplies rollback-resistant current time to protected cache replay.
pub(crate) trait CacheResidencyCurrentTimeAuthorityV1: Send + Sync {
    /// Advances and returns the protected wall-clock floor.
    fn current_unix_seconds(&self) -> Result<u64, CacheResidencyProtectedJournalErrorV1>;
}

pub(crate) struct ProtectedCacheResidencyReplayAuthorityV1 {
    journal: Mutex<Journal>,
    owner_scope: ObjectDigest,
    maximum_record_bytes: usize,
    partitions: Mutex<BTreeMap<ObjectDigest, CacheResidencyReplayPartitionEvidenceV1>>,
    current_time: Arc<dyn CacheResidencyCurrentTimeAuthorityV1>,
    limits: CacheRecoveryLimitsV1,
}

struct CacheResidencyAuthoritySessionV1 {
    owner_scope: ObjectDigest,
    partitions: BTreeMap<ObjectDigest, CacheResidencyAuthoritySessionPartitionV1>,
    effect_observations: BTreeMap<Vec<u8>, Vec<u8>>,
}

struct CacheResidencyAuthoritySessionPartitionV1 {
    evidence: CacheResidencyReplayPartitionEvidenceV1,
    scope: CacheAuthorityScopeV1,
    record_digest: ObjectDigest,
}

impl CacheResidencyReplayAuthorityV1 for CacheResidencyAuthoritySessionV1 {
    fn partitions(&self) -> Result<Vec<PhysicalPartitionId>, RecoveryError> {
        Ok(self
            .partitions
            .values()
            .map(|partition| partition.evidence.partition)
            .collect())
    }

    fn validate_partition(
        &self,
        partition: PhysicalPartitionId,
        published_checkpoints: &[Vec<u8>],
        records: &[Vec<u8>],
        limits: CacheRecoveryLimitsV1,
    ) -> Result<CacheRecoveryInventoryV1, RecoveryError> {
        let session = self
            .partitions
            .get(&partition.digest())
            .ok_or(RecoveryError::AnchorMismatch)?;
        let evidence = &session.evidence;
        if evidence.partition != partition
            || evidence.purpose != CacheAuthorityPurposeV1::Replay
            || evidence.scope != session.scope
            || (!published_checkpoints.is_empty()
                && (!published_checkpoints
                    .iter()
                    .any(|checkpoint| checkpoint == &evidence.typed_checkpoint)
                    || published_checkpoints.iter().any(|checkpoint| {
                        checkpoint != &evidence.typed_checkpoint
                            && evidence.prior_typed_checkpoint.as_ref() != Some(checkpoint)
                    })))
        {
            return Err(RecoveryError::AnchorMismatch);
        }
        CacheRecoveryInventoryV1::from_authority_session(
            partition,
            &evidence.typed_checkpoint,
            evidence.prior_typed_checkpoint.as_deref(),
            evidence.floor,
            records.iter().cloned(),
            limits,
            session.scope,
            session.record_digest,
        )
    }

    fn effect_observation_is_authentic(
        &self,
        transaction_id: [u8; 16],
        transaction_digest: ObjectDigest,
        partition: ObjectDigest,
        evidence: ObjectDigest,
    ) -> bool {
        let key = cache_effect_observation_authority_key(transaction_id);
        let expected = encode_cache_effect_observation_authority(
            self.owner_scope,
            transaction_id,
            transaction_digest,
            partition,
            evidence,
        );
        self.effect_observations
            .get(&key)
            .is_some_and(|value| value.as_slice() == expected.as_slice())
    }
}

impl ProtectedCacheResidencyReplayAuthorityV1 {
    pub(crate) fn current_replay_partition_evidence(
        &self,
    ) -> Result<Vec<CacheResidencyReplayPartitionEvidenceV1>, CacheResidencyProtectedJournalErrorV1>
    {
        self.while_authority_current(&[], |_owner, _capabilities, _now, _validator, refresh| {
            let evidence = self
                .partitions
                .lock()
                .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?
                .values()
                .cloned()
                .collect();
            refresh()?;
            Ok(evidence)
        })
    }

    pub(crate) fn while_authority_current<T>(
        &self,
        requests: &[(CacheAuthorityPurposeV1, Vec<u8>)],
        action: impl FnOnce(
            &CacheAuthorityOwner<'_, '_>,
            &[super::VerifiedCacheCapabilityV1],
            u64,
            CacheResidencyReplayValidatorV1,
            &dyn Fn() -> Result<u64, CacheResidencyProtectedJournalErrorV1>,
        ) -> Result<T, CacheResidencyProtectedJournalErrorV1>,
    ) -> Result<T, CacheResidencyProtectedJournalErrorV1> {
        let now = self.current_time.current_unix_seconds()?;
        let mut journal = self
            .journal
            .lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let authority = journal
            .claim_protected_authority(RecordNamespace::DesiredState)
            .map_err(ProtectedDomainJournalErrorV1::from)?;
        let owner =
            CacheAuthorityOwner::new(&authority, self.owner_scope, self.maximum_record_bytes)
                .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
        let capabilities = requests
            .iter()
            .map(|(purpose, key)| {
                owner
                    .verify_current_record_for_purpose(*purpose, key)
                    .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if capabilities
            .iter()
            .any(|capability| now == 0 || now >= capability.scope().valid_until())
        {
            return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
        }

        let partitions = self
            .partitions
            .lock()
            .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?
            .clone();
        let mut replay_capabilities = Vec::with_capacity(partitions.len());
        let mut session_partitions = BTreeMap::new();
        for evidence in partitions.values() {
            let capability = owner
                .verify_current_record(evidence.purpose, evidence.scope, &evidence.record_key)
                .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
            if now >= capability.scope().valid_until() {
                return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
            }
            session_partitions.insert(
                evidence.partition.digest(),
                CacheResidencyAuthoritySessionPartitionV1 {
                    evidence: evidence.clone(),
                    scope: capability.scope(),
                    record_digest: capability.record_digest(),
                },
            );
            replay_capabilities.push((evidence.purpose, capability));
        }
        let effect_observations = authority
            .records()
            .map_err(ProtectedDomainJournalErrorV1::from)?
            .into_iter()
            .filter(|(key, _)| key.starts_with(EFFECT_OBSERVATION_AUTHORITY_KEY_PREFIX))
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect();
        let session_validator = CacheResidencyReplayValidatorV1::new(
            Arc::new(CacheResidencyAuthoritySessionV1 {
                owner_scope: self.owner_scope,
                partitions: session_partitions,
                effect_observations,
            }),
            self.limits,
        )?;

        let result = {
            let refresh = || {
                let current = self.current_time.current_unix_seconds()?;
                for ((purpose, _), capability) in requests.iter().zip(&capabilities) {
                    owner
                        .validate_for_effect_at(capability, *purpose, capability.scope(), current)
                        .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
                }
                for (purpose, capability) in &replay_capabilities {
                    owner
                        .validate_for_effect_at(capability, *purpose, capability.scope(), current)
                        .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
                }
                Ok(current)
            };
            action(&owner, &capabilities, now, session_validator, &refresh)
        };
        let final_current = self.current_time.current_unix_seconds()?;
        for ((purpose, _), capability) in requests.iter().zip(&capabilities) {
            owner
                .validate_for_effect_at(capability, *purpose, capability.scope(), final_current)
                .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
        }
        for (purpose, capability) in replay_capabilities {
            owner
                .validate_for_effect_at(&capability, purpose, capability.scope(), final_current)
                .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
        }
        result
    }
}

impl CacheResidencyReplayAuthorityV1 for ProtectedCacheResidencyReplayAuthorityV1 {
    fn partitions(&self) -> Result<Vec<PhysicalPartitionId>, RecoveryError> {
        Ok(self
            .partitions
            .lock()
            .map_err(|_| RecoveryError::AnchorMismatch)?
            .values()
            .map(|partition| partition.partition)
            .collect())
    }

    fn validate_partition(
        &self,
        partition: PhysicalPartitionId,
        published_checkpoints: &[Vec<u8>],
        records: &[Vec<u8>],
        limits: CacheRecoveryLimitsV1,
    ) -> Result<CacheRecoveryInventoryV1, RecoveryError> {
        let evidence = self
            .partitions
            .lock()
            .map_err(|_| RecoveryError::AnchorMismatch)?
            .get(&partition.digest())
            .cloned()
            .ok_or(RecoveryError::AnchorMismatch)?;
        let now = self
            .current_time
            .current_unix_seconds()
            .map_err(|_| RecoveryError::AnchorMismatch)?;
        if evidence.partition != partition
            || evidence.purpose != CacheAuthorityPurposeV1::Replay
            || evidence.record_key.is_empty()
            || now == 0
            || now >= evidence.scope.valid_until()
            || (!published_checkpoints.is_empty()
                && (!published_checkpoints
                    .iter()
                    .any(|checkpoint| checkpoint == &evidence.typed_checkpoint)
                    || published_checkpoints.iter().any(|checkpoint| {
                        checkpoint != &evidence.typed_checkpoint
                            && evidence.prior_typed_checkpoint.as_ref() != Some(checkpoint)
                    })))
        {
            return Err(RecoveryError::AnchorMismatch);
        }
        let mut journal = self
            .journal
            .lock()
            .map_err(|_| RecoveryError::AnchorMismatch)?;
        let authority = journal
            .claim_protected_authority(RecordNamespace::DesiredState)
            .map_err(|_| RecoveryError::AnchorMismatch)?;
        let owner =
            CacheAuthorityOwner::new(&authority, self.owner_scope, self.maximum_record_bytes)?;
        let capability =
            owner.verify_current_record(evidence.purpose, evidence.scope, &evidence.record_key)?;
        CacheRecoveryInventoryV1::from_verified(
            &owner,
            &capability,
            partition,
            &evidence.typed_checkpoint,
            evidence.prior_typed_checkpoint.as_deref(),
            evidence.floor,
            records.iter().cloned(),
            limits,
            now,
        )
    }

    fn effect_observation_is_authentic(
        &self,
        transaction_id: [u8; 16],
        transaction_digest: ObjectDigest,
        partition: ObjectDigest,
        evidence: ObjectDigest,
    ) -> bool {
        let key = cache_effect_observation_authority_key(transaction_id);
        let expected = encode_cache_effect_observation_authority(
            self.owner_scope,
            transaction_id,
            transaction_digest,
            partition,
            evidence,
        );
        let Ok(mut journal) = self.journal.lock() else {
            return false;
        };
        let Ok(authority) = journal.claim_protected_authority(RecordNamespace::DesiredState) else {
            return false;
        };
        authority
            .get(&key)
            .ok()
            .flatten()
            .is_some_and(|value| value == expected.as_slice())
    }
}

impl CacheResidencyReplayValidatorV1 {
    /// Constructs the sole core-owned replay callback from protected evidence.
    ///
    /// # Errors
    ///
    /// Returns [`CacheResidencyProtectedJournalErrorV1`] for invalid limits,
    /// duplicate partitions, sentinel configuration, or unprotected authority.
    pub(crate) fn from_protected_authority(
        mut journal: Journal,
        owner_scope: ObjectDigest,
        maximum_record_bytes: usize,
        evidence: Vec<CacheResidencyReplayPartitionEvidenceV1>,
        limits: CacheRecoveryLimitsV1,
        current_time: Arc<dyn CacheResidencyCurrentTimeAuthorityV1>,
    ) -> Result<
        (Self, Arc<ProtectedCacheResidencyReplayAuthorityV1>),
        CacheResidencyProtectedJournalErrorV1,
    > {
        if owner_scope.as_bytes() == &[0; 32] || evidence.is_empty() {
            return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let limits = limits
            .validate()
            .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
        let mut partitions = BTreeMap::new();
        {
            let authority = journal
                .claim_protected_authority(RecordNamespace::DesiredState)
                .map_err(ProtectedDomainJournalErrorV1::from)?;
            let owner = CacheAuthorityOwner::new(&authority, owner_scope, maximum_record_bytes)
                .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
            for item in evidence {
                let now = current_time.current_unix_seconds()?;
                if now == 0
                    || item.purpose != CacheAuthorityPurposeV1::Replay
                    || now >= item.scope.valid_until()
                    || item.scope.partition() != item.partition.digest()
                    || decode_typed_checkpoint(item.partition, &item.typed_checkpoint, limits)
                        .is_err()
                    || item
                        .prior_typed_checkpoint
                        .as_ref()
                        .is_some_and(|checkpoint| {
                            decode_typed_checkpoint(item.partition, checkpoint, limits).is_err()
                        })
                {
                    return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
                }
                let capability = owner
                    .verify_current_record(item.purpose, item.scope, &item.record_key)
                    .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
                // A newly provisioned partition has no state records yet, so
                // its checkpoint and floor must be checked here as well.
                CacheRecoveryInventoryV1::from_verified(
                    &owner,
                    &capability,
                    item.partition,
                    &item.typed_checkpoint,
                    item.prior_typed_checkpoint.as_deref(),
                    item.floor,
                    std::iter::empty(),
                    limits,
                    now,
                )
                .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
                if partitions.insert(item.partition.digest(), item).is_some() {
                    return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
                }
            }
        }
        let authority = Arc::new(ProtectedCacheResidencyReplayAuthorityV1 {
            journal: Mutex::new(journal),
            owner_scope,
            maximum_record_bytes,
            partitions: Mutex::new(partitions),
            current_time,
            limits,
        });
        let validator = Self::new(authority.clone(), limits)?;
        Ok((validator, authority))
    }

    fn effect_observation_is_authentic(
        &self,
        transaction_id: [u8; 16],
        transaction_digest: ObjectDigest,
        partition: ObjectDigest,
        evidence: ObjectDigest,
    ) -> bool {
        self.authority.effect_observation_is_authentic(
            transaction_id,
            transaction_digest,
            partition,
            evidence,
        )
    }
}

impl ProtectedDomainSchemaV1 for CacheResidencyProtectedJournalSchemaV1 {
    type Kind = CacheResidencyProtectedRecordKindV1;
    type ReplayValidator = CacheResidencyReplayValidatorV1;

    const MAGIC: [u8; 8] = *b"AOSCRJ01";
    const HASH_DOMAIN: &'static [u8] = b"aos.sandbox.cache-residency.protected-journal.v1\0";
    const KEY_PREFIX: &'static [u8] = b"\0aos-cache-residency-v1\0";
    const MAXIMUM_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

    fn kind_code(kind: Self::Kind) -> u8 {
        kind as u8
    }

    fn kind_from_code(code: u8) -> Option<Self::Kind> {
        match code {
            1 => Some(Self::Kind::Authority),
            2 => Some(Self::Kind::GlobalAccounting),
            3 => Some(Self::Kind::ProjectAccounting),
            4 => Some(Self::Kind::DomainAccounting),
            5 => Some(Self::Kind::Reservation),
            6 => Some(Self::Kind::Pin),
            7 => Some(Self::Kind::Scrub),
            8 => Some(Self::Kind::Eviction),
            9 => Some(Self::Kind::Catalog),
            10 => Some(Self::Kind::Effect),
            11 => Some(Self::Kind::Current),
            12 => Some(Self::Kind::Checkpoint),
            13 => Some(Self::Kind::EffectObservation),
            _ => None,
        }
    }

    fn namespace(kind: Self::Kind) -> RecordNamespace {
        match kind {
            Self::Kind::Effect => RecordNamespace::Effect,
            Self::Kind::Current => RecordNamespace::AuthorityPublication,
            Self::Kind::Checkpoint => RecordNamespace::RuntimeGeneration,
            Self::Kind::EffectObservation => RecordNamespace::DesiredState,
            _ => RecordNamespace::DesiredState,
        }
    }

    fn order(kind: Self::Kind) -> u8 {
        kind as u8
    }

    fn role(kind: Self::Kind) -> ProtectedRecordRoleV1 {
        match kind {
            Self::Kind::Effect => ProtectedRecordRoleV1::Effect,
            Self::Kind::Current | Self::Kind::Checkpoint => ProtectedRecordRoleV1::Publication,
            Self::Kind::EffectObservation => ProtectedRecordRoleV1::State,
            _ => ProtectedRecordRoleV1::State,
        }
    }

    fn is_checkpoint(_kind: Self::Kind) -> bool {
        false
    }

    fn family(kind: Self::Kind) -> u8 {
        match kind {
            Self::Kind::Authority => 1,
            Self::Kind::GlobalAccounting
            | Self::Kind::ProjectAccounting
            | Self::Kind::DomainAccounting => 2,
            Self::Kind::Reservation => 3,
            Self::Kind::Pin => 4,
            Self::Kind::Scrub => 5,
            Self::Kind::Eviction => 6,
            Self::Kind::Catalog => 7,
            Self::Kind::Effect => 8,
            Self::Kind::Current => 9,
            Self::Kind::Checkpoint => 10,
            Self::Kind::EffectObservation => 11,
        }
    }

    fn decode_reducer_phase(
        validator: &Self::ReplayValidator,
        kind: Self::Kind,
        identity: &[u8],
        body: &[u8],
    ) -> Option<ProtectedReducerPhaseV1> {
        if kind == Self::Kind::EffectObservation {
            return decode_cache_effect_observation(identity, body)
                .map(|_| ProtectedReducerPhaseV1::Observed);
        }
        decode_cache_body(kind, identity, body, validator).map(|_| match kind {
            Self::Kind::Effect => ProtectedReducerPhaseV1::Prepared,
            Self::Kind::Scrub | Self::Kind::Eviction => ProtectedReducerPhaseV1::Observed,
            Self::Kind::EffectObservation => ProtectedReducerPhaseV1::Observed,
            _ => ProtectedReducerPhaseV1::Terminal,
        })
    }

    fn validates_identity(kind: Self::Kind, identity: &[u8]) -> bool {
        let expected_length = if kind == Self::Kind::EffectObservation {
            16
        } else if kind == Self::Kind::Checkpoint {
            81
        } else {
            121
        };
        if identity.len() != expected_length
            || (kind == Self::Kind::EffectObservation && identity == [0; 16])
        {
            return false;
        }
        if kind == Self::Kind::EffectObservation {
            return true;
        }
        if identity[..32] == [0; 32]
            || identity[49..81] == [0; 32]
            || (expected_length == 121
                && (identity[81..89] == [0; 8] || identity[89..121] == [0; 32]))
        {
            return false;
        }
        match kind {
            Self::Kind::ProjectAccounting => identity[32] == 1 && identity[33..49] != [0; 16],
            Self::Kind::DomainAccounting => identity[32] == 2 && identity[33..49] != [0; 16],
            _ => identity[32] == 0 && identity[33..49] == [0; 16],
        }
    }

    fn semantic_tuple(kind: Self::Kind, identity: &[u8], body: &[u8]) -> Option<[u8; 32]> {
        if kind == Self::Kind::EffectObservation {
            return None;
        }
        let _ = (kind, body);
        if identity.len() < 81 {
            return None;
        }
        Some(
            Sha256::new()
                .chain_update(b"aos.sandbox.cache-residency.semantic-tuple.v1\0")
                .chain_update(&identity[..49])
                .finalize()
                .into(),
        )
    }
}

const fn cache_body_magic(kind: CacheResidencyProtectedRecordKindV1) -> [u8; 8] {
    match kind {
        CacheResidencyProtectedRecordKindV1::Authority => *b"AOSCRA01",
        CacheResidencyProtectedRecordKindV1::GlobalAccounting => *b"AOSCRG01",
        CacheResidencyProtectedRecordKindV1::ProjectAccounting => *b"AOSCRP01",
        CacheResidencyProtectedRecordKindV1::DomainAccounting => *b"AOSCRD01",
        CacheResidencyProtectedRecordKindV1::Reservation => *b"AOSCRR01",
        CacheResidencyProtectedRecordKindV1::Pin => *b"AOSCRN01",
        CacheResidencyProtectedRecordKindV1::Scrub => *b"AOSCRS01",
        CacheResidencyProtectedRecordKindV1::Eviction => *b"AOSCRE01",
        CacheResidencyProtectedRecordKindV1::Catalog => *b"AOSCRC01",
        CacheResidencyProtectedRecordKindV1::Effect => *b"AOSCRX01",
        CacheResidencyProtectedRecordKindV1::Current => *b"AOSCRU01",
        CacheResidencyProtectedRecordKindV1::Checkpoint => *b"AOSCRT01",
        CacheResidencyProtectedRecordKindV1::EffectObservation => *b"AOSCRY01",
    }
}

const fn cache_identity_length_matches(
    kind: CacheResidencyProtectedRecordKindV1,
    length: usize,
) -> bool {
    match kind {
        CacheResidencyProtectedRecordKindV1::EffectObservation => length == 16,
        CacheResidencyProtectedRecordKindV1::Checkpoint => length == 81,
        _ => length == 121,
    }
}

/// Classifies one cache transaction without reducing its exact payloads to flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheResidencyTransactionKindV1 {
    /// Reserves capacity before any immutable destination work can escape.
    Admission,
    /// Changes a pin while updating all three accounting scopes atomically.
    PinChange,
    /// Commits a scrub or quarantine result after rechecking current pins.
    Scrub,
    /// Commits an eviction decision before releasing unlink authority.
    EvictionPrepare,
    /// Credits reclaimed bytes only after durable reclamation evidence.
    EvictionFinalize,
    /// Reconstructs an exact interrupted transition without broadening it.
    Recovery,
    /// Publishes a replay join for a future globally validated floor.
    Checkpoint,
}

/// Canonical cache shared-journal key.
pub type CacheResidencyProtectedJournalKeyV1 =
    ProtectedDomainKeyV1<CacheResidencyProtectedJournalSchemaV1>;
/// Canonical cache value and predecessor CAS.
pub type CacheResidencyProtectedJournalEnvelopeV1 =
    ProtectedDomainEnvelopeV1<CacheResidencyProtectedJournalSchemaV1>;
/// Sealed cache currentness snapshot.
pub type CacheResidencyProtectedJournalSnapshotV1 =
    ProtectedDomainSnapshotV1<CacheResidencyProtectedJournalSchemaV1>;
/// Replayed complete cache projection.
pub type CacheResidencyProtectedJournalProjectionV1 =
    ProtectedDomainProjectionV1<CacheResidencyProtectedJournalSchemaV1>;
type RawCacheResidencyPostcommitCapabilityV1 =
    DomainPostcommitCapabilityV1<CacheResidencyProtectedJournalSchemaV1>;

/// Composite cache authority released after exact transaction readback.
#[must_use = "cache authority must be revalidated against its exact journal"]
pub struct CacheResidencyPostcommitCapabilityV1 {
    kind: CacheResidencyTransactionKindV1,
    inner: RawCacheResidencyPostcommitCapabilityV1,
}

/// Carries one fully revalidated cache transaction.
#[must_use = "validated cache authority must be handed to one dormant consumer"]
pub struct ValidatedCacheResidencyPostcommitV1<'current> {
    kind: CacheResidencyTransactionKindV1,
    inner: ValidatedDomainPostcommitV1<'current, CacheResidencyProtectedJournalSchemaV1>,
    // The grant is derived from the latest protected projection, not merely
    // the historical transaction that originally changed this pin.
    current_pin_effect: Option<CurrentPhysicalPinEffectV1>,
}

/// Retains cold-replayed cache state without granting fresh effect authority.
#[must_use = "cold cache state may be observed but not replayed as a fresh effect"]
pub struct CacheResidencyColdObservationV1 {
    inner: RawCacheResidencyPostcommitCapabilityV1,
    transaction_id: [u8; 16],
}

/// Cache adapter validation or durability failure.
pub type CacheResidencyProtectedJournalErrorV1 = ProtectedDomainJournalErrorV1;

/// Holds one exact cache transaction and its closed semantic shape.
#[must_use = "a prepared cache transaction must be committed or deliberately discarded"]
pub struct PreparedCacheResidencyTransactionV1 {
    kind: CacheResidencyTransactionKindV1,
    inner: PreparedDomainTransactionV1<CacheResidencyProtectedJournalSchemaV1>,
}

/// Retains an exact cache transaction whose durable outcome is unknown.
#[must_use = "an ambiguous cache commit must be resolved after protected reopen"]
pub struct CacheResidencyOutcomeUnknownV1 {
    kind: CacheResidencyTransactionKindV1,
    inner: CacheResidencyOutcomeUnknownStateV1,
}

enum CacheResidencyOutcomeUnknownStateV1 {
    Commit(DomainOutcomeUnknownV1<CacheResidencyProtectedJournalSchemaV1>),
    PostcommitValidation(AppliedDomainTransactionV1<CacheResidencyProtectedJournalSchemaV1>),
}

/// Releases exact cache postcommit authority and no storage capability.
#[must_use = "cache postcommit authority must be consumed or deliberately discarded"]
pub struct AppliedCacheResidencyTransactionV1 {
    kind: CacheResidencyTransactionKindV1,
    inner: AppliedDomainTransactionV1<CacheResidencyProtectedJournalSchemaV1>,
}

impl AppliedCacheResidencyTransactionV1 {
    /// Returns the closed transition represented by the durable transaction.
    #[must_use]
    pub const fn kind(&self) -> CacheResidencyTransactionKindV1 {
        self.kind
    }

    /// Takes the composite authority for exact current revalidation.
    #[must_use]
    pub fn take_postcommit(&mut self) -> Option<CacheResidencyPostcommitCapabilityV1> {
        if self.kind == CacheResidencyTransactionKindV1::Recovery {
            return None;
        }
        Some(CacheResidencyPostcommitCapabilityV1 {
            kind: self.kind,
            inner: self.inner.take_postcommit()?,
        })
    }
}

/// Distinguishes cache commit success from an outcome requiring reopen.
#[must_use = "ambiguous cache commits retain mandatory recovery state"]
pub enum CacheResidencyCommitOutcomeV1 {
    /// The complete successor transaction is durable and was read back.
    Applied(AppliedCacheResidencyTransactionV1),
    /// The exact transaction must be classified against a protected reopen.
    OutcomeUnknown {
        /// Retains the complete predecessor and successor transaction.
        pending: CacheResidencyOutcomeUnknownV1,
        /// Reports the underlying durability failure.
        cause: JournalError,
    },
    /// Exact durable readback succeeded, but protected cache authority could
    /// not yet validate the resulting complete projection.
    ValidationUnknown {
        /// Retains the exact applied transaction until full replay succeeds.
        pending: CacheResidencyOutcomeUnknownV1,
        /// Reports why protected cache authority could not classify readback.
        cause: CacheResidencyProtectedJournalErrorV1,
    },
}

/// Classifies protected recovery of one exact cache transaction.
#[must_use = "cache recovery must be applied, retried, or quarantined"]
pub enum CacheResidencyRecoveryV1 {
    /// Protected reopen found every exact successor.
    Applied(AppliedCacheResidencyTransactionV1),
    /// Protected reopen found every predecessor and retained an exact retry.
    Retry(PreparedCacheResidencyTransactionV1),
    /// Protected reopen found mixed or substituted cache state.
    Diverged(CacheResidencyOutcomeUnknownV1),
    /// Full protected replay could not yet classify the retained exact state.
    Indeterminate {
        /// Retains the exact transaction for another protected recovery pass.
        pending: CacheResidencyOutcomeUnknownV1,
        /// Reports the fail-closed replay or authority failure.
        cause: CacheResidencyProtectedJournalErrorV1,
    },
}

/// Classifies a complete cache transaction reconstructed after cold reopen.
#[must_use = "cold cache recovery may grant observation authority only"]
pub enum CacheResidencyColdRecoveryV1 {
    /// A state-only or incomplete group grants no postcommit authority.
    StateOnly,
    /// A pending effect is retained solely for physical observation.
    ObservePending(CacheResidencyColdObservationV1),
    /// A terminal publication may be revalidated as one exact transaction.
    Terminal(CacheResidencyColdObservationV1),
}

/// Owns dormant cache-residency durability over a protected-open journal.
pub struct CacheResidencyProtectedJournalV1<'journal> {
    inner: ProtectedDomainJournalV1<'journal, CacheResidencyProtectedJournalSchemaV1>,
    validator: CacheResidencyReplayValidatorV1,
}

impl<'journal> CacheResidencyProtectedJournalV1<'journal> {
    /// Claims the closed cache adapter without activating a service.
    ///
    /// # Errors
    ///
    /// Returns [`CacheResidencyProtectedJournalErrorV1`] unless the journal has
    /// protected storage provenance and a healthy replay boundary.
    pub(crate) fn claim(
        journal: &'journal mut Journal,
        validator: CacheResidencyReplayValidatorV1,
    ) -> Result<Self, CacheResidencyProtectedJournalErrorV1> {
        Ok(Self {
            inner: ProtectedDomainJournalV1::claim_with_validator(journal, validator.clone())?,
            validator,
        })
    }

    /// Replays the complete typed cache projection.
    ///
    /// # Errors
    ///
    /// Returns [`CacheResidencyProtectedJournalErrorV1`] for malformed,
    /// substituted, or excessive state.
    pub fn replay(
        &self,
    ) -> Result<CacheResidencyProtectedJournalProjectionV1, CacheResidencyProtectedJournalErrorV1>
    {
        let projection = self.inner.replay()?;
        validate_cache_projection(&projection, &self.validator)?;
        Ok(projection)
    }

    /// Captures exact cache currentness.
    ///
    /// # Errors
    ///
    /// Returns [`CacheResidencyProtectedJournalErrorV1`] when replay fails.
    pub fn snapshot(
        &self,
    ) -> Result<CacheResidencyProtectedJournalSnapshotV1, CacheResidencyProtectedJournalErrorV1>
    {
        self.replay()?;
        Ok(self.inner.snapshot()?)
    }

    /// Plans one atomic transition after validating its required record family.
    ///
    /// # Errors
    ///
    /// Returns [`CacheResidencyProtectedJournalErrorV1`] for a missing or
    /// forbidden record kind, mixed partition, stale CAS, or failed preflight.
    pub(crate) fn plan(
        &self,
        transaction_id: [u8; 16],
        kind: CacheResidencyTransactionKindV1,
        successors: Vec<CacheResidencyProtectedJournalEnvelopeV1>,
    ) -> Result<PreparedCacheResidencyTransactionV1, CacheResidencyProtectedJournalErrorV1> {
        let projection = self.replay()?;
        validate_cache_transition(kind, &successors, &self.validator)?;
        validate_cache_history(
            projection.records().iter().chain(successors.iter()),
            &self.validator,
        )?;
        let inner = self.inner.plan(transaction_id, successors)?;
        Ok(PreparedCacheResidencyTransactionV1 { kind, inner })
    }

    /// Commits one cache transition and performs exact readback.
    ///
    /// # Errors
    ///
    /// Returns [`CacheResidencyProtectedJournalErrorV1`] for stale authority or
    /// an invalid protected-journal operation.
    pub fn commit(
        &mut self,
        prepared: PreparedCacheResidencyTransactionV1,
    ) -> Result<CacheResidencyCommitOutcomeV1, CacheResidencyProtectedJournalErrorV1> {
        self.replay()?;
        let kind = prepared.kind;
        let outcome = self.inner.commit(prepared.inner)?;
        match outcome {
            DomainCommitOutcomeV1::Applied(inner) => {
                if let Err(cause) = self.replay() {
                    return Ok(CacheResidencyCommitOutcomeV1::ValidationUnknown {
                        pending: CacheResidencyOutcomeUnknownV1 {
                            kind,
                            inner: CacheResidencyOutcomeUnknownStateV1::PostcommitValidation(inner),
                        },
                        cause,
                    });
                }
                Ok(CacheResidencyCommitOutcomeV1::Applied(
                    AppliedCacheResidencyTransactionV1 { kind, inner },
                ))
            }
            DomainCommitOutcomeV1::OutcomeUnknown { pending, cause } => {
                Ok(CacheResidencyCommitOutcomeV1::OutcomeUnknown {
                    pending: CacheResidencyOutcomeUnknownV1 {
                        kind,
                        inner: CacheResidencyOutcomeUnknownStateV1::Commit(pending),
                    },
                    cause,
                })
            }
        }
    }

    /// Resolves an exact ambiguous cache commit after protected reopen.
    ///
    pub fn recover(&self, pending: CacheResidencyOutcomeUnknownV1) -> CacheResidencyRecoveryV1 {
        if let Err(cause) = self.replay() {
            return CacheResidencyRecoveryV1::Indeterminate { pending, cause };
        }
        let kind = pending.kind;
        let inner = match pending.inner {
            CacheResidencyOutcomeUnknownStateV1::PostcommitValidation(inner) => {
                return CacheResidencyRecoveryV1::Applied(AppliedCacheResidencyTransactionV1 {
                    kind,
                    inner,
                });
            }
            CacheResidencyOutcomeUnknownStateV1::Commit(inner) => inner,
        };
        let recovery = match self.inner.recover_retaining(inner) {
            DomainRetainedRecoveryV1::Outcome(recovery) => recovery,
            DomainRetainedRecoveryV1::Retryable { pending, error } => {
                return CacheResidencyRecoveryV1::Indeterminate {
                    pending: CacheResidencyOutcomeUnknownV1 {
                        kind,
                        inner: CacheResidencyOutcomeUnknownStateV1::Commit(pending),
                    },
                    cause: error,
                };
            }
        };
        match recovery {
            DomainRecoveryV1::Applied(inner) => {
                if let Err(cause) = self.replay() {
                    return CacheResidencyRecoveryV1::Indeterminate {
                        pending: CacheResidencyOutcomeUnknownV1 {
                            kind,
                            inner: CacheResidencyOutcomeUnknownStateV1::PostcommitValidation(inner),
                        },
                        cause,
                    };
                }
                CacheResidencyRecoveryV1::Applied(AppliedCacheResidencyTransactionV1 {
                    kind,
                    inner,
                })
            }
            DomainRecoveryV1::Retry(inner) => {
                CacheResidencyRecoveryV1::Retry(PreparedCacheResidencyTransactionV1 { kind, inner })
            }
            DomainRecoveryV1::Diverged(inner) => {
                CacheResidencyRecoveryV1::Diverged(CacheResidencyOutcomeUnknownV1 {
                    kind,
                    inner: CacheResidencyOutcomeUnknownStateV1::Commit(inner),
                })
            }
        }
    }

    /// Reconstructs one bounded durable transaction after cold reopen.
    ///
    /// Pending effects are observation-only: this API never authorizes blind
    /// repetition of an unlink, scrub, admission, or backing operation.
    ///
    /// # Errors
    ///
    /// Returns [`CacheResidencyProtectedJournalErrorV1`] when grouping or the
    /// complete cache projection is malformed.
    pub fn recover_current_transaction(
        &self,
        transaction_id: [u8; 16],
    ) -> Result<CacheResidencyColdRecoveryV1, CacheResidencyProtectedJournalErrorV1> {
        let projection = self.replay()?;
        if let Some(settlement) = projection.records().iter().find(|record| {
            record.key().kind() == CacheResidencyProtectedRecordKindV1::EffectObservation
                && record.key().identity() == transaction_id
        }) {
            let body = decode_reducer_payload_with_validator::<
                CacheResidencyProtectedJournalSchemaV1,
            >(settlement.key(), settlement.payload(), &self.validator)?;
            let settlement =
                decode_cache_effect_observation(settlement.key().identity(), body.body())
                    .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
            let capability = match self.inner.recover_current_postcommit(transaction_id)? {
                Some(ReplayedDomainPostcommitV1::Prepared(capability))
                | Some(ReplayedDomainPostcommitV1::Terminal(capability)) => capability,
                None => return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord),
            };
            let validated = capability.consume(&self.inner)?;
            if validated.transaction_digest() != settlement.transaction_digest
                || !validated.records().iter().any(|record| {
                    record.envelope().key().identity().get(..32)
                        == Some(settlement.partition.as_bytes())
                })
            {
                return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
            }
            return Ok(CacheResidencyColdRecoveryV1::StateOnly);
        }
        Ok(
            match self.inner.recover_current_postcommit(transaction_id)? {
                Some(ReplayedDomainPostcommitV1::Prepared(capability)) => {
                    CacheResidencyColdRecoveryV1::ObservePending(CacheResidencyColdObservationV1 {
                        inner: capability,
                        transaction_id,
                    })
                }
                Some(ReplayedDomainPostcommitV1::Terminal(capability)) => {
                    CacheResidencyColdRecoveryV1::Terminal(CacheResidencyColdObservationV1 {
                        inner: capability,
                        transaction_id,
                    })
                }
                None => CacheResidencyColdRecoveryV1::StateOnly,
            },
        )
    }

    /// Plans a protected observation that permanently suppresses cold effect replay.
    ///
    /// # Errors
    ///
    /// Returns [`CacheResidencyProtectedJournalErrorV1`] unless the cold
    /// capability and verified observation bind the same exact transaction.
    pub(crate) fn plan_cold_observation(
        &self,
        settlement_transaction_id: [u8; 16],
        cold: CacheResidencyColdObservationV1,
        evidence: ObjectDigest,
    ) -> Result<PreparedCacheResidencyTransactionV1, CacheResidencyProtectedJournalErrorV1> {
        if settlement_transaction_id == cold.transaction_id || evidence.as_bytes() == &[0; 32] {
            return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let validated = cold.inner.consume(&self.inner)?;
        if validated
            .records()
            .iter()
            .filter(|record| record.is_effect())
            .count()
            != 1
        {
            return Err(CacheResidencyProtectedJournalErrorV1::StaleAuthority);
        }
        let partition = validated
            .records()
            .iter()
            .find_map(|record| record.envelope().key().identity().get(..32))
            .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
        let partition = ObjectDigest::from_bytes(
            partition
                .try_into()
                .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?,
        );
        let transaction_digest = validated.transaction_digest();
        if !self.validator.effect_observation_is_authentic(
            cold.transaction_id,
            transaction_digest,
            partition,
            evidence,
        ) {
            return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let body = encode_cache_effect_observation(CacheEffectObservationV1 {
            transaction_id: cold.transaction_id,
            transaction_digest,
            evidence,
            partition,
        });
        let key = CacheResidencyProtectedJournalKeyV1::new(
            CacheResidencyProtectedRecordKindV1::EffectObservation,
            cold.transaction_id.to_vec(),
        )?;
        let payload = encode_reducer_payload_with_validator::<
            CacheResidencyProtectedJournalSchemaV1,
        >(&key, &body, &self.validator)?;
        let envelope = CacheResidencyProtectedJournalEnvelopeV1::new_with_validator(
            key,
            1,
            None,
            payload,
            &self.validator,
        )?;
        drop(validated);
        self.plan(
            settlement_transaction_id,
            CacheResidencyTransactionKindV1::Recovery,
            vec![envelope],
        )
    }

    /// Plans an immutable replay join without granting compaction authority.
    ///
    /// # Errors
    ///
    /// Returns [`CacheResidencyProtectedJournalErrorV1`] for a sentinel
    /// checkpoint, stale projection, or failed journal preflight.
    pub fn plan_checkpoint(
        &self,
        transaction_id: [u8; 16],
        partition: PhysicalPartitionId,
        checkpoint: &CacheTypedCheckpointV1,
    ) -> Result<PreparedCacheResidencyTransactionV1, CacheResidencyProtectedJournalErrorV1> {
        let key = cache_residency_protected_key_v1(
            CacheResidencyProtectedRecordKindV1::Checkpoint,
            partition,
            None,
            checkpoint.digest,
            None,
        )?;
        let encoded = encode_typed_checkpoint(checkpoint, partition, self.validator.limits)
            .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
        let descriptor = encode_partition_descriptor(partition);
        let mut body = Vec::with_capacity(8 + descriptor.len() + encoded.len());
        body.extend_from_slice(&cache_body_magic(
            CacheResidencyProtectedRecordKindV1::Checkpoint,
        ));
        body.extend_from_slice(&descriptor);
        body.extend_from_slice(&encoded);
        let payload = encode_reducer_payload_with_validator::<
            CacheResidencyProtectedJournalSchemaV1,
        >(&key, &body, &self.validator)?;
        let envelope = CacheResidencyProtectedJournalEnvelopeV1::new_with_validator(
            key,
            1,
            None,
            payload,
            &self.validator,
        )?;
        self.plan(
            transaction_id,
            CacheResidencyTransactionKindV1::Checkpoint,
            vec![envelope],
        )
    }
}

impl CacheResidencyPostcommitCapabilityV1 {
    /// Consumes this capability after full authority-backed cache replay.
    ///
    /// # Errors
    ///
    /// Returns [`CacheResidencyProtectedJournalErrorV1`] when the journal or
    /// the protected cache history, journal snapshot, or any durable
    /// transaction member changed after readback.
    pub fn consume<'current>(
        self,
        authority: &'current CacheResidencyProtectedJournalV1<'_>,
    ) -> Result<ValidatedCacheResidencyPostcommitV1<'current>, CacheResidencyProtectedJournalErrorV1>
    {
        let projection = authority.replay()?;
        let inner = self.inner.consume(&authority.inner)?;
        let records = inner
            .records()
            .iter()
            .map(|record| record.envelope().clone())
            .collect::<Vec<_>>();
        let current_pin_effect = current_physical_pin_effect(
            self.kind,
            &records,
            projection.records(),
            &authority.validator,
        )?;
        Ok(ValidatedCacheResidencyPostcommitV1 {
            kind: self.kind,
            inner,
            current_pin_effect,
        })
    }
}

impl CacheResidencyColdObservationV1 {
    /// Consumes cold terminal authority against the adapter that recovered it.
    ///
    /// # Errors
    ///
    /// Returns an error when full replay or the exact journal snapshot changed.
    pub(crate) fn consume<'current>(
        self,
        authority: &'current CacheResidencyProtectedJournalV1<'_>,
    ) -> Result<ValidatedCacheResidencyPostcommitV1<'current>, CacheResidencyProtectedJournalErrorV1>
    {
        let projection = authority.replay()?;
        let inner = self.inner.consume(&authority.inner)?;
        let records = inner
            .records()
            .iter()
            .map(|record| record.envelope().clone())
            .collect::<Vec<_>>();
        let kind = classify_replayed_cache_transaction(&records)?;
        let current_pin_effect = current_physical_pin_effect(
            kind,
            &records,
            projection.records(),
            &authority.validator,
        )?;
        Ok(ValidatedCacheResidencyPostcommitV1 {
            kind,
            inner,
            current_pin_effect,
        })
    }
}

impl ValidatedCacheResidencyPostcommitV1<'_> {
    /// Returns the exact durable transaction commitment.
    #[must_use]
    pub const fn transaction_digest(&self) -> ObjectDigest {
        self.inner.transaction_digest()
    }

    /// Confirms that this exact protected transaction carries the supplied
    /// still-reserved immutable admission. This check is intentionally
    /// crate-private: only the fixed Linux effect owner consumes it.
    pub(crate) fn authorizes_reserved_admission(
        &self,
        plan: &super::ImmutableAdmissionPlanV1,
        reservation: &super::CacheReservationV1,
        limits: CacheRecoveryLimitsV1,
    ) -> bool {
        if reservation.state != super::ReservationStateV1::Reserved
            || reservation.plan_digest != plan.digest
            || reservation.id != plan.reservation
            || reservation.descriptor != plan.descriptor
            || reservation.partition != plan.partition
            || reservation.reserved_bytes < plan.descriptor.encoded_size()
            || plan.reserved_bytes < plan.descriptor.encoded_size()
        {
            return false;
        }

        self.inner.records().iter().any(|record| {
            if !record.is_effect() {
                return false;
            }
            let body = record.envelope().payload();
            let descriptor_end = 8 + PARTITION_DESCRIPTOR_BYTES;
            if body.len() <= descriptor_end
                || decode_partition_descriptor(&body[8..descriptor_end]) != Some(plan.partition)
            {
                return false;
            }
            decode_atomic_object_record(plan.partition, &body[descriptor_end..], limits)
                .is_ok_and(|payload| payload.plan == *plan && payload.reservation == *reservation)
        })
    }
}

#[cfg(target_os = "linux")]
impl ValidatedCacheResidencyPostcommitV1<'_> {
    /// Settles one current protected pin event against the durable physical owner.
    ///
    /// A renewal verifies its existing physical pin rather than acquiring a
    /// second one. A stale historical transaction cannot authorize either
    /// action because its current physical effect is absent.
    ///
    /// # Errors
    ///
    /// Returns an error for stale protected authority, conflicting or absent
    /// owner pins, exhausted limits, or a failed durable owner update.
    pub fn settle_cache_owner_pin_change(
        self,
        owner: &mut super::DormantCacheOwnerV1,
    ) -> Result<super::CacheOwnerPinSettlementV1, super::CacheOwnerPinSettlementErrorV1> {
        if self.kind != CacheResidencyTransactionKindV1::PinChange {
            return Err(CacheResidencyProtectedJournalErrorV1::StaleAuthority.into());
        }
        let physical = self
            .current_pin_effect
            .as_ref()
            .ok_or(CacheResidencyProtectedJournalErrorV1::StaleAuthority)?;
        if physical.action == CurrentPhysicalPinActionV1::Retain {
            let partition = physical.pin.partition;
            let id = super::CacheOwnerPinIdV1::for_cache_pin(partition, physical.pin.id)?;
            if owner.observe_pin(id, partition, &physical.pin.object)?
                != super::CacheOwnerPinPresenceV1::Present
            {
                return Err(super::CacheOwnerErrorV1::RecoveryMismatch.into());
            }
            return Ok(super::CacheOwnerPinSettlementV1::Retained(
                owner.currentness(),
            ));
        }

        let admission = self.into_cache_owner_pin_admission(owner)?;
        let observation = owner.apply_pin_change(admission)?;
        Ok(super::CacheOwnerPinSettlementV1::Changed(observation))
    }

    /// Reconciles one current pin event after cold protected and physical replay.
    ///
    /// Exact owner-manifest presence distinguishes an already settled action
    /// from one that still needs an effect. The protected transaction must
    /// remain current, and the owner admission fences any intervening manifest
    /// replacement. This does not grant blind replay of a generic cache effect.
    ///
    /// # Errors
    ///
    /// Returns an error for stale protected authority, a conflicting physical
    /// pin identity, or a failed durable owner update.
    pub fn reconcile_cache_owner_pin_change(
        self,
        owner: &mut super::DormantCacheOwnerV1,
        expected_action: super::CacheOwnerPinActionV1,
        expected_pin: &CachePinV1,
    ) -> Result<super::CacheOwnerPinReconciliationV1, super::CacheOwnerPinSettlementErrorV1> {
        if self.kind != CacheResidencyTransactionKindV1::PinChange {
            return Err(CacheResidencyProtectedJournalErrorV1::StaleAuthority.into());
        }
        let physical = self
            .current_pin_effect
            .as_ref()
            .ok_or(CacheResidencyProtectedJournalErrorV1::StaleAuthority)?;
        let action_matches = matches!(
            (expected_action, physical.action),
            (
                super::CacheOwnerPinActionV1::Acquire,
                CurrentPhysicalPinActionV1::Acquire | CurrentPhysicalPinActionV1::Retain
            ) | (
                super::CacheOwnerPinActionV1::Release,
                CurrentPhysicalPinActionV1::Release
            )
        );
        if !action_matches || &physical.pin != expected_pin {
            return Err(CacheResidencyProtectedJournalErrorV1::StaleAuthority.into());
        }
        let partition = physical.pin.partition;
        let id = super::CacheOwnerPinIdV1::for_cache_pin(partition, physical.pin.id)?;
        let presence = owner.observe_pin(id, partition, &physical.pin.object)?;
        match (physical.action, presence) {
            (CurrentPhysicalPinActionV1::Retain, super::CacheOwnerPinPresenceV1::Present) => Ok(
                super::CacheOwnerPinReconciliationV1::Retained(owner.currentness()),
            ),
            (CurrentPhysicalPinActionV1::Retain, super::CacheOwnerPinPresenceV1::Absent) => {
                Err(super::CacheOwnerErrorV1::RecoveryMismatch.into())
            }
            (CurrentPhysicalPinActionV1::Acquire, super::CacheOwnerPinPresenceV1::Present) => {
                Ok(super::CacheOwnerPinReconciliationV1::Acquired(
                    super::CacheOwnerPinReconciliationStateV1::AlreadySettled(owner.currentness()),
                ))
            }
            (CurrentPhysicalPinActionV1::Release, super::CacheOwnerPinPresenceV1::Absent) => {
                Ok(super::CacheOwnerPinReconciliationV1::Released(
                    super::CacheOwnerPinReconciliationStateV1::AlreadySettled(owner.currentness()),
                ))
            }
            (action, _) => {
                let settlement = self.settle_cache_owner_pin_change(owner)?;
                let super::CacheOwnerPinSettlementV1::Changed(observation) = settlement else {
                    return Err(CacheResidencyProtectedJournalErrorV1::StaleAuthority.into());
                };
                let settled = super::CacheOwnerPinReconciliationStateV1::Changed(observation);
                Ok(match action {
                    CurrentPhysicalPinActionV1::Acquire => {
                        super::CacheOwnerPinReconciliationV1::Acquired(settled)
                    }
                    CurrentPhysicalPinActionV1::Release => {
                        super::CacheOwnerPinReconciliationV1::Released(settled)
                    }
                    CurrentPhysicalPinActionV1::Retain => {
                        return Err(CacheResidencyProtectedJournalErrorV1::StaleAuthority.into());
                    }
                })
            }
        }
    }

    /// Issues one single-use physical admission from an exact reserved record.
    ///
    /// # Errors
    ///
    /// Returns [`CacheResidencyProtectedJournalErrorV1::StaleAuthority`] unless
    /// this transaction contains the byte-exact reserved plan and reservation.
    pub fn into_cache_owner_admission(
        self,
        plan: ImmutableAdmissionPlanV1,
        reservation: super::CacheReservationV1,
        limits: CacheRecoveryLimitsV1,
    ) -> Result<super::CacheOwnerAdmissionV1, CacheResidencyProtectedJournalErrorV1> {
        if !self.authorizes_reserved_admission(&plan, &reservation, limits) {
            return Err(CacheResidencyProtectedJournalErrorV1::StaleAuthority);
        }
        Ok(super::CacheOwnerAdmissionV1::from_verified(
            self,
            plan,
            reservation,
        ))
    }

    /// Consumes current postcommit authority into one physical pin transition.
    ///
    /// A logical renewal changes only lease authority and cannot acquire a
    /// second physical owner pin. The owner admission derives its exact action,
    /// partition, and object from this event, never from caller-supplied fields.
    ///
    /// # Errors
    ///
    /// Returns stale authority unless the committed transaction is a pin change.
    pub fn into_cache_owner_pin_admission(
        self,
        owner: &super::DormantCacheOwnerV1,
    ) -> Result<super::CacheOwnerPinAdmissionV1, CacheResidencyProtectedJournalErrorV1> {
        let physical = self
            .current_pin_effect
            .as_ref()
            .ok_or(CacheResidencyProtectedJournalErrorV1::StaleAuthority)?;
        let action = match physical.action {
            CurrentPhysicalPinActionV1::Acquire => super::CacheOwnerPinActionV1::Acquire,
            CurrentPhysicalPinActionV1::Release => super::CacheOwnerPinActionV1::Release,
            CurrentPhysicalPinActionV1::Retain => {
                return Err(CacheResidencyProtectedJournalErrorV1::StaleAuthority);
            }
        };
        let partition = physical.pin.partition;
        let descriptor = physical.pin.object.clone();
        let (predecessor, maximum_pins, maximum_pinned_bytes) = owner.pin_grant_context();
        if self.kind != CacheResidencyTransactionKindV1::PinChange
            || maximum_pins == 0
            || maximum_pinned_bytes < descriptor.encoded_size()
        {
            return Err(CacheResidencyProtectedJournalErrorV1::StaleAuthority);
        }
        let id = super::CacheOwnerPinIdV1::for_cache_pin(partition, physical.pin.id)
            .map_err(|_| CacheResidencyProtectedJournalErrorV1::StaleAuthority)?;
        Ok(super::CacheOwnerPinAdmissionV1::from_verified(
            self.transaction_digest(),
            action,
            id,
            partition,
            descriptor,
            predecessor,
            maximum_pins,
            maximum_pinned_bytes,
        ))
    }

    /// Consumes current protected postcommit authority into one eviction pass.
    ///
    /// # Errors
    ///
    /// Returns stale authority unless the transaction durably prepared eviction.
    pub fn into_cache_owner_eviction_admission(
        self,
        plan: super::FrozenEvictionPlanV1,
        owner: &super::DormantCacheOwnerV1,
        limits: CacheRecoveryLimitsV1,
    ) -> Result<super::CacheOwnerEvictionAdmissionV1, CacheResidencyProtectedJournalErrorV1> {
        let exact_plan = self.inner.records().iter().any(|record| {
            let body = record.envelope().payload();
            let descriptor_end = 8 + PARTITION_DESCRIPTOR_BYTES;
            if record.envelope().key().kind() != CacheResidencyProtectedRecordKindV1::Eviction
                || body.len() <= descriptor_end
                || decode_partition_descriptor(&body[8..descriptor_end]) != Some(plan.partition)
            {
                return false;
            }
            decode_atomic_object_record(plan.partition, &body[descriptor_end..], limits)
                .is_ok_and(|payload| payload.eviction_plan.as_ref() == Some(&plan))
        });
        if self.kind != CacheResidencyTransactionKindV1::EvictionPrepare || !exact_plan {
            return Err(CacheResidencyProtectedJournalErrorV1::StaleAuthority);
        }
        let victims = plan
            .candidates
            .iter()
            .map(|candidate| {
                (
                    plan.partition,
                    candidate.descriptor.clone(),
                    candidate.physical_bytes,
                    candidate.last_use_generation,
                    candidate.canonical_name,
                    candidate.root_custody,
                )
            })
            .collect();
        let predecessor = owner.eviction_grant_predecessor();
        Ok(super::CacheOwnerEvictionAdmissionV1::from_verified(
            self.transaction_digest(),
            predecessor,
            plan.target_reclaim_bytes,
            victims,
        ))
    }
}

/// Constructs one closed reducer envelope from a canonical cache event.
///
/// # Errors
///
/// Returns [`CacheResidencyProtectedJournalErrorV1`] unless the durable event
/// round-trips, matches the protected kind/key, and derives its exact joins.
pub(crate) fn cache_residency_reducer_envelope_v1(
    key: CacheResidencyProtectedJournalKeyV1,
    revision: u64,
    predecessor: Option<ObjectDigest>,
    partition: PhysicalPartitionId,
    payload: &CacheAtomicObjectPayloadV1,
    validator: &CacheResidencyReplayValidatorV1,
) -> Result<CacheResidencyProtectedJournalEnvelopeV1, CacheResidencyProtectedJournalErrorV1> {
    let limits = validator.limits;
    let record = payload.record;
    if !cache_record_kind_matches(key.kind(), record.kind)
        || key.identity()[..32] != *partition.digest().as_bytes()
        || record.partition != partition.digest()
        || key.identity()[49..81] != *record.subject.as_bytes()
        || (!matches!(key.kind(), CacheResidencyProtectedRecordKindV1::Checkpoint)
            && (key.identity()[81..89] != record.sequence.to_be_bytes()
                || key.identity()[89..121] != *record.digest.as_bytes()))
        || (key.kind() == CacheResidencyProtectedRecordKindV1::ProjectAccounting
            && key.identity()[33..49] != *payload.plan.project.as_bytes())
        || (key.kind() == CacheResidencyProtectedRecordKindV1::DomainAccounting
            && key.identity()[33..49] != *partition.disclosure().domain_id().as_bytes())
    {
        return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
    }
    let encoded_record = encode_atomic_object_record(payload, limits)
        .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
    let partition_descriptor = encode_partition_descriptor(partition);
    let mut canonical_body =
        Vec::with_capacity(8 + partition_descriptor.len() + encoded_record.len());
    canonical_body.extend_from_slice(&cache_body_magic(key.kind()));
    canonical_body.extend_from_slice(&partition_descriptor);
    canonical_body.extend_from_slice(&encoded_record);
    let payload = encode_reducer_payload_with_validator::<CacheResidencyProtectedJournalSchemaV1>(
        &key,
        &canonical_body,
        validator,
    )?;
    CacheResidencyProtectedJournalEnvelopeV1::new_with_validator(
        key,
        revision,
        predecessor,
        payload,
        validator,
    )
}

/// Constructs a bounded cache key bound to one partition and optional project.
///
/// # Errors
///
/// Returns [`CacheResidencyProtectedJournalErrorV1`] for sentinel commitments,
/// a sentinel project, or a noncanonical project/accounting shape.
pub fn cache_residency_protected_key_v1(
    kind: CacheResidencyProtectedRecordKindV1,
    partition: PhysicalPartitionId,
    project: Option<ProjectId>,
    subject: ObjectDigest,
    retained_record: Option<(u64, ObjectDigest)>,
) -> Result<CacheResidencyProtectedJournalKeyV1, CacheResidencyProtectedJournalErrorV1> {
    let retains_history = kind != CacheResidencyProtectedRecordKindV1::Checkpoint;
    if subject.as_bytes() == &[0; 32]
        || project.is_some_and(|value| value.as_bytes() == &[0; 16])
        || (kind == CacheResidencyProtectedRecordKindV1::ProjectAccounting) != project.is_some()
        || retains_history != retained_record.is_some()
        || retained_record
            .is_some_and(|(sequence, digest)| sequence == 0 || digest.as_bytes() == &[0; 32])
    {
        return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
    }
    let mut identity = Vec::with_capacity(if retains_history { 121 } else { 81 });
    identity.extend_from_slice(partition.digest().as_bytes());
    match kind {
        CacheResidencyProtectedRecordKindV1::ProjectAccounting => {
            identity.push(1);
            identity.extend_from_slice(
                project
                    .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?
                    .as_bytes(),
            );
        }
        CacheResidencyProtectedRecordKindV1::DomainAccounting => {
            identity.push(2);
            identity.extend_from_slice(partition.disclosure().domain_id().as_bytes());
        }
        _ => {
            identity.push(0);
            identity.extend_from_slice(&[0; 16]);
        }
    }
    identity.extend_from_slice(subject.as_bytes());
    if let Some((sequence, digest)) = retained_record {
        identity.extend_from_slice(&sequence.to_be_bytes());
        identity.extend_from_slice(digest.as_bytes());
    }
    CacheResidencyProtectedJournalKeyV1::new(kind, identity)
}

fn validate_cache_transition(
    transition: CacheResidencyTransactionKindV1,
    successors: &[CacheResidencyProtectedJournalEnvelopeV1],
    validator: &CacheResidencyReplayValidatorV1,
) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
    if transition == CacheResidencyTransactionKindV1::Recovery {
        return if successors.len() == 1
            && successors[0].key().kind() == CacheResidencyProtectedRecordKindV1::EffectObservation
            && successors[0].revision() == 1
            && successors[0].predecessor().is_none()
        {
            Ok(())
        } else {
            Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)
        };
    }
    let Some(first) = successors.first() else {
        return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
    };
    let partition = first.key().identity().get(..32);
    if partition.is_none()
        || successors.iter().any(|successor| {
            successor.key().identity().get(..32) != partition
                || validate_cache_key(successor.key()).is_err()
                || (!matches!(
                    successor.key().kind(),
                    CacheResidencyProtectedRecordKindV1::Checkpoint
                ) && (successor.revision() != 1 || successor.predecessor().is_some()))
        })
    {
        return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
    }
    if !matches!(
        transition,
        CacheResidencyTransactionKindV1::Checkpoint | CacheResidencyTransactionKindV1::Recovery
    ) {
        let mut operation = None;
        let mut sequences = std::collections::BTreeSet::new();
        let mut decoded = Vec::with_capacity(successors.len());
        for successor in successors {
            let reducer = decode_reducer_payload_with_validator::<
                CacheResidencyProtectedJournalSchemaV1,
            >(successor.key(), successor.payload(), validator)?;
            validate_cache_body(
                successor.key().kind(),
                successor.key().identity(),
                reducer.body(),
                validator,
            )?;
            let record = decode_cache_body(
                successor.key().kind(),
                successor.key().identity(),
                reducer.body(),
                validator,
            )
            .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?
            .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
            if successor.key().identity()[..32] != *record.partition.as_bytes()
                || successor.key().identity()[49..81] != *record.subject.as_bytes()
                || operation.is_some_and(|current| current != record.operation)
                || (transition != CacheResidencyTransactionKindV1::PinChange
                    && !sequences.insert(record.sequence))
            {
                return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
            }
            operation = Some(record.operation);
            decoded.push((successor.key().kind(), record));
        }
        decoded.sort_by_key(|(kind, _)| CacheResidencyProtectedJournalSchemaV1::order(*kind));
        let shared = decoded
            .first()
            .map(|(_, record)| record)
            .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
        if transition == CacheResidencyTransactionKindV1::PinChange {
            // Accounting and Current are aliases of the one atomic Pin event.
            // They cannot invent quota changes or advance durable history.
            if shared.kind != CacheRecordKindV1::Pin
                || decoded.iter().any(|(_, record)| record != shared)
            {
                return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
            }
        } else if decoded.iter().any(|(kind, record)| {
            matches!(
                kind,
                CacheResidencyProtectedRecordKindV1::GlobalAccounting
                    | CacheResidencyProtectedRecordKindV1::ProjectAccounting
                    | CacheResidencyProtectedRecordKindV1::DomainAccounting
            ) && record.kind != CacheRecordKindV1::Quota
        }) {
            return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
        } else if decoded.windows(2).any(|pair| {
            pair[0].1.sequence.checked_add(1) != Some(pair[1].1.sequence)
                || pair[0].1.operation != pair[1].1.operation
        }) {
            return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
        }
        if decoded.iter().skip(1).any(|(_, record)| {
            record.plan != shared.plan
                || record.model != shared.model
                || record.payload != shared.payload
                || record.catalog_projection != shared.catalog_projection
                || record.reservation_projection != shared.reservation_projection
                || record.pin_projection != shared.pin_projection
                || record.progress_projection != shared.progress_projection
        }) {
            return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let accounting = |kind| {
            decoded
                .iter()
                .find(|(candidate, _)| *candidate == kind)
                .map(|(_, record)| record)
        };
        if let (Some(global), Some(project), Some(domain)) = (
            accounting(CacheResidencyProtectedRecordKindV1::GlobalAccounting),
            accounting(CacheResidencyProtectedRecordKindV1::ProjectAccounting),
            accounting(CacheResidencyProtectedRecordKindV1::DomainAccounting),
        ) && transition != CacheResidencyTransactionKindV1::PinChange
        {
            if global.amount < project.amount
                || project.amount < domain.amount
                || global.model != project.model
                || project.model != domain.model
            {
                return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
            }
        }
    }
    let has = |kind| successors.iter().any(|value| value.key().kind() == kind);
    let count = |kind| {
        successors
            .iter()
            .filter(|value| value.key().kind() == kind)
            .count()
    };
    let only = |allowed: &[CacheResidencyProtectedRecordKindV1]| {
        successors
            .iter()
            .all(|value| allowed.contains(&value.key().kind()))
    };
    use CacheResidencyProtectedRecordKindV1 as Record;
    let valid = match transition {
        CacheResidencyTransactionKindV1::Admission => {
            successors.len() == 9
                && count(Record::Authority) == 1
                && count(Record::GlobalAccounting) == 1
                && count(Record::ProjectAccounting) == 1
                && count(Record::DomainAccounting) == 1
                && count(Record::Reservation) == 1
                && count(Record::Pin) == 1
                && count(Record::Catalog) == 1
                && count(Record::Effect) == 1
                && count(Record::Current) == 1
                && only(&[
                    Record::Authority,
                    Record::GlobalAccounting,
                    Record::ProjectAccounting,
                    Record::DomainAccounting,
                    Record::Reservation,
                    Record::Pin,
                    Record::Catalog,
                    Record::Effect,
                    Record::Current,
                ])
        }
        CacheResidencyTransactionKindV1::PinChange => {
            successors.len() == 5
                && count(Record::GlobalAccounting) == 1
                && count(Record::ProjectAccounting) == 1
                && count(Record::DomainAccounting) == 1
                && count(Record::Pin) == 1
                && count(Record::Current) == 1
                && only(&[
                    Record::GlobalAccounting,
                    Record::ProjectAccounting,
                    Record::DomainAccounting,
                    Record::Pin,
                    Record::Current,
                ])
        }
        CacheResidencyTransactionKindV1::Scrub => {
            successors.len() == 5
                && count(Record::Authority) == 1
                && count(Record::Pin) == 1
                && count(Record::Scrub) == 1
                && count(Record::Catalog) == 1
                && count(Record::Current) == 1
                && only(&[
                    Record::Authority,
                    Record::Pin,
                    Record::Scrub,
                    Record::Catalog,
                    Record::Current,
                ])
        }
        CacheResidencyTransactionKindV1::EvictionPrepare => {
            successors.len() == 6
                && count(Record::Authority) == 1
                && count(Record::Pin) == 1
                && count(Record::Eviction) == 1
                && count(Record::Catalog) == 1
                && count(Record::Effect) == 1
                && count(Record::Current) == 1
                && only(&[
                    Record::Authority,
                    Record::Pin,
                    Record::Eviction,
                    Record::Catalog,
                    Record::Effect,
                    Record::Current,
                ])
        }
        CacheResidencyTransactionKindV1::EvictionFinalize => {
            successors.len() == 8
                && count(Record::GlobalAccounting) == 1
                && count(Record::ProjectAccounting) == 1
                && count(Record::DomainAccounting) == 1
                && count(Record::Pin) == 1
                && count(Record::Scrub) == 1
                && count(Record::Eviction) == 1
                && count(Record::Catalog) == 1
                && count(Record::Current) == 1
                && !has(Record::Effect)
                && only(&[
                    Record::GlobalAccounting,
                    Record::ProjectAccounting,
                    Record::DomainAccounting,
                    Record::Pin,
                    Record::Scrub,
                    Record::Eviction,
                    Record::Catalog,
                    Record::Current,
                ])
        }
        CacheResidencyTransactionKindV1::Recovery => {
            successors.len() == 1 && has(Record::EffectObservation)
        }
        CacheResidencyTransactionKindV1::Checkpoint => {
            successors.len() == 1 && has(Record::Checkpoint)
        }
    };
    if !valid {
        return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
    }
    Ok(())
}

fn validate_cache_projection(
    projection: &CacheResidencyProtectedJournalProjectionV1,
    validator: &CacheResidencyReplayValidatorV1,
) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
    validate_cache_history(projection.records(), validator)?;

    let mut original_transactions = BTreeMap::<[u8; 16], Vec<(ObjectDigest, ObjectDigest)>>::new();
    let mut observations = BTreeMap::<[u8; 16], CacheEffectObservationV1>::new();
    for envelope in projection.records().iter().filter(|envelope| {
        envelope.key().kind() == CacheResidencyProtectedRecordKindV1::EffectObservation
    }) {
        let reducer = decode_reducer_payload_with_validator::<
            CacheResidencyProtectedJournalSchemaV1,
        >(envelope.key(), envelope.payload(), validator)?;
        let observation =
            decode_cache_effect_observation(envelope.key().identity(), reducer.body())
                .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
        if observations
            .insert(observation.transaction_id, observation)
            .is_some()
        {
            return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
        }
    }
    let mut grouped_observations = BTreeMap::<[u8; 16], CacheEffectObservationV1>::new();
    for transaction in projection.transactions() {
        if transaction.phase() != ProtectedDomainReplayPhaseV1::Incomplete {
            validate_cache_transition(
                classify_replayed_cache_transaction(transaction.records())?,
                transaction.records(),
                validator,
            )?;
        }
        if transaction.records().iter().any(|record| {
            record.key().kind() == CacheResidencyProtectedRecordKindV1::EffectObservation
        }) {
            if transaction.records().len() != 1
                || transaction.phase() != ProtectedDomainReplayPhaseV1::Observed
            {
                return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
            }
            let envelope = &transaction.records()[0];
            let reducer = decode_reducer_payload_with_validator::<
                CacheResidencyProtectedJournalSchemaV1,
            >(envelope.key(), envelope.payload(), validator)?;
            let observation =
                decode_cache_effect_observation(envelope.key().identity(), reducer.body())
                    .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
            if grouped_observations
                .insert(observation.transaction_id, observation)
                .is_some()
            {
                return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
            }
            continue;
        }
        if transaction.phase() != ProtectedDomainReplayPhaseV1::Prepared
            || transaction
                .records()
                .iter()
                .filter(|record| record.key().kind() == CacheResidencyProtectedRecordKindV1::Effect)
                .count()
                != 1
        {
            continue;
        }
        if let Some(partition) = cache_transaction_partition(transaction.records())? {
            original_transactions
                .entry(transaction.transaction_id())
                .or_default()
                .push((transaction.transaction_digest(), partition));
        }
    }
    if grouped_observations != observations {
        return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
    }
    for (transaction_id, observation) in observations {
        let matches = original_transactions
            .get(&transaction_id)
            .into_iter()
            .flatten()
            .filter(|(digest, partition)| {
                *digest == observation.transaction_digest && *partition == observation.partition
            })
            .count();
        if matches != 1 {
            return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
        }
    }
    Ok(())
}

fn validate_cache_history<'envelope>(
    envelopes: impl IntoIterator<Item = &'envelope CacheResidencyProtectedJournalEnvelopeV1>,
    validator: &CacheResidencyReplayValidatorV1,
) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
    reconstruct_cache_history(envelopes, validator).map(|_| ())
}

/// Reconstructs every custodied partition, including checkpoint-only state.
pub(super) fn reconstruct_cache_history<'envelope>(
    envelopes: impl IntoIterator<Item = &'envelope CacheResidencyProtectedJournalEnvelopeV1>,
    validator: &CacheResidencyReplayValidatorV1,
) -> Result<Vec<CacheRecoveryInventoryV1>, CacheResidencyProtectedJournalErrorV1> {
    let mut partitions = BTreeMap::<ObjectDigest, PhysicalPartitionId>::new();
    for partition in validator
        .authority
        .partitions()
        .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?
    {
        if partitions.insert(partition.digest(), partition).is_some() {
            return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
        }
    }
    let mut records_by_partition = BTreeMap::<ObjectDigest, BTreeMap<u64, Vec<u8>>>::new();
    let mut checkpoints_by_partition = BTreeMap::<ObjectDigest, Vec<Vec<u8>>>::new();
    for envelope in envelopes {
        validate_cache_key(envelope.key())?;
        if envelope.key().kind() == CacheResidencyProtectedRecordKindV1::EffectObservation {
            let reducer = decode_reducer_payload_with_validator::<
                CacheResidencyProtectedJournalSchemaV1,
            >(envelope.key(), envelope.payload(), validator)?;
            decode_cache_effect_observation(envelope.key().identity(), reducer.body())
                .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
            continue;
        }
        let reducer = decode_reducer_payload_with_validator::<
            CacheResidencyProtectedJournalSchemaV1,
        >(envelope.key(), envelope.payload(), validator)?;
        let descriptor_end = 8 + PARTITION_DESCRIPTOR_BYTES;
        let partition = decode_partition_descriptor(
            reducer
                .body()
                .get(8..descriptor_end)
                .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?,
        )
        .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
        let partition_digest = partition.digest();
        if partitions
            .insert(partition_digest, partition)
            .is_some_and(|value| value != partition)
        {
            return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
        }
        if envelope.key().kind() == CacheResidencyProtectedRecordKindV1::Checkpoint {
            checkpoints_by_partition
                .entry(partition_digest)
                .or_default()
                .push(reducer.body()[descriptor_end..].to_vec());
            continue;
        }
        let record = decode_cache_body(
            envelope.key().kind(),
            envelope.key().identity(),
            reducer.body(),
            validator,
        )
        .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?
        .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
        let encoded_record = &reducer.body()[descriptor_end..];
        let pin_alias = record.kind == CacheRecordKindV1::Pin
            && matches!(
                envelope.key().kind(),
                CacheResidencyProtectedRecordKindV1::GlobalAccounting
                    | CacheResidencyProtectedRecordKindV1::ProjectAccounting
                    | CacheResidencyProtectedRecordKindV1::DomainAccounting
                    | CacheResidencyProtectedRecordKindV1::Pin
                    | CacheResidencyProtectedRecordKindV1::Current
            );
        match records_by_partition
            .entry(partition_digest)
            .or_default()
            .entry(record.sequence)
        {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(encoded_record.to_vec());
            }
            std::collections::btree_map::Entry::Occupied(entry)
                if pin_alias && entry.get().as_slice() == encoded_record => {}
            std::collections::btree_map::Entry::Occupied(_) => {
                return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
            }
        }
    }
    let mut inventories = Vec::with_capacity(partitions.len());
    for (partition_digest, partition) in partitions {
        let checkpoints = checkpoints_by_partition
            .remove(&partition_digest)
            .unwrap_or_default();
        let records = records_by_partition
            .remove(&partition_digest)
            .unwrap_or_default()
            .into_values()
            .collect::<Vec<_>>();
        let inventory = validator
            .authority
            .validate_partition(partition, &checkpoints, &records, validator.limits)
            .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
        if let Some(last) = records.last() {
            let decoded = decode_atomic_object_record(partition, last, validator.limits)
                .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
            if inventory.head_sequence != decoded.record.sequence
                || inventory.head_digest != decoded.record.digest
            {
                return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
            }
        }
        inventories.push(inventory);
    }
    Ok(inventories)
}

fn cache_transaction_partition(
    records: &[CacheResidencyProtectedJournalEnvelopeV1],
) -> Result<Option<ObjectDigest>, CacheResidencyProtectedJournalErrorV1> {
    let mut partition = None;
    for record in records {
        if matches!(
            record.key().kind(),
            CacheResidencyProtectedRecordKindV1::Checkpoint
                | CacheResidencyProtectedRecordKindV1::EffectObservation
        ) {
            continue;
        }
        let candidate = ObjectDigest::from_bytes(
            record.key().identity()[..32]
                .try_into()
                .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?,
        );
        if partition.is_some_and(|retained| retained != candidate) {
            return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
        }
        partition = Some(candidate);
    }
    Ok(partition)
}

fn validate_cache_body(
    kind: CacheResidencyProtectedRecordKindV1,
    identity: &[u8],
    body: &[u8],
    validator: &CacheResidencyReplayValidatorV1,
) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
    if decode_cache_body(kind, identity, body, validator).is_none() {
        return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
    }
    Ok(())
}

fn decode_cache_body(
    kind: CacheResidencyProtectedRecordKindV1,
    identity: &[u8],
    body: &[u8],
    validator: &CacheResidencyReplayValidatorV1,
) -> Option<Option<CacheDurableRecordV1>> {
    if body.len() <= 8 + PARTITION_DESCRIPTOR_BYTES
        || body[..8] != cache_body_magic(kind)
        || !cache_identity_length_matches(kind, identity.len())
    {
        return None;
    }
    let descriptor_end = 8 + PARTITION_DESCRIPTOR_BYTES;
    let partition = decode_partition_descriptor(&body[8..descriptor_end])?;
    let limits = validator.limits;
    if kind == CacheResidencyProtectedRecordKindV1::Checkpoint {
        let checkpoint =
            decode_typed_checkpoint(partition, &body[descriptor_end..], limits).ok()?;
        if encode_typed_checkpoint(&checkpoint, partition, limits)
            .ok()?
            .as_slice()
            != &body[descriptor_end..]
            || identity[..32] != *partition.digest().as_bytes()
            || identity[49..81] != *checkpoint.digest.as_bytes()
        {
            return None;
        }
        return Some(None);
    }
    let payload = decode_atomic_object_record(partition, &body[descriptor_end..], limits).ok()?;
    if encode_atomic_object_record(&payload, limits)
        .ok()?
        .as_slice()
        != &body[descriptor_end..]
        || encode_partition_descriptor(partition).as_slice() != &body[8..descriptor_end]
        || identity[..32] != *partition.digest().as_bytes()
        || payload.record.partition != partition.digest()
        || !cache_record_kind_matches(kind, payload.record.kind)
        || identity[49..81] != *payload.record.subject.as_bytes()
        || (identity.len() == 121
            && (identity[81..89] != payload.record.sequence.to_be_bytes()
                || identity[89..121] != *payload.record.digest.as_bytes()))
        || (kind == CacheResidencyProtectedRecordKindV1::ProjectAccounting
            && identity[33..49] != *payload.plan.project.as_bytes())
        || (kind == CacheResidencyProtectedRecordKindV1::DomainAccounting
            && identity[33..49] != *partition.disclosure().domain_id().as_bytes())
    {
        return None;
    }
    Some(Some(payload.record))
}

pub(crate) fn decode_cache_payload_for_lifecycle(
    envelope: &CacheResidencyProtectedJournalEnvelopeV1,
    validator: &CacheResidencyReplayValidatorV1,
) -> Result<Option<CacheAtomicObjectPayloadV1>, CacheResidencyProtectedJournalErrorV1> {
    let kind = envelope.key().kind();
    if matches!(
        kind,
        CacheResidencyProtectedRecordKindV1::Checkpoint
            | CacheResidencyProtectedRecordKindV1::EffectObservation
    ) {
        return Ok(None);
    }
    let reducer = decode_reducer_payload_with_validator::<CacheResidencyProtectedJournalSchemaV1>(
        envelope.key(),
        envelope.payload(),
        validator,
    )?;
    let body = reducer.body();
    if body.len() <= 8 + PARTITION_DESCRIPTOR_BYTES || body[..8] != cache_body_magic(kind) {
        return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
    }
    let descriptor_end = 8 + PARTITION_DESCRIPTOR_BYTES;
    let partition = decode_partition_descriptor(&body[8..descriptor_end])
        .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
    let payload = decode_atomic_object_record(partition, &body[descriptor_end..], validator.limits)
        .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
    if encode_atomic_object_record(&payload, validator.limits)
        .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?
        .as_slice()
        != &body[descriptor_end..]
    {
        return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
    }
    Ok(Some(payload))
}

pub(crate) fn encode_partition_descriptor(
    partition: PhysicalPartitionId,
) -> [u8; PARTITION_DESCRIPTOR_BYTES] {
    let mut bytes = [0_u8; PARTITION_DESCRIPTOR_BYTES];
    bytes[..8].copy_from_slice(PARTITION_DESCRIPTOR_MAGIC);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..32].copy_from_slice(partition.node().as_bytes());
    let backing = partition.backing();
    bytes[32..64].copy_from_slice(backing.root().as_bytes());
    bytes[64..96].copy_from_slice(backing.dataset().as_bytes());
    bytes[96..128].copy_from_slice(backing.pool().as_bytes());
    bytes[128..160].copy_from_slice(backing.backend().as_bytes());
    bytes[160] = match partition.disclosure().kind() {
        CacheDomainKind::Private => 1,
        CacheDomainKind::Project => 2,
        CacheDomainKind::TrustDomain => 3,
        CacheDomainKind::Public => 4,
    };
    bytes[161..177].copy_from_slice(partition.disclosure().domain_id().as_bytes());
    bytes[177..209].copy_from_slice(partition.isolation_policy().as_bytes());
    bytes[209..].copy_from_slice(partition.digest().as_bytes());
    bytes
}

pub(crate) fn decode_partition_descriptor(bytes: &[u8]) -> Option<PhysicalPartitionId> {
    if bytes.len() != PARTITION_DESCRIPTOR_BYTES
        || &bytes[..8] != PARTITION_DESCRIPTOR_MAGIC
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10..16] != [0; 6]
    {
        return None;
    }
    let array =
        |start: usize| -> Option<[u8; 32]> { bytes.get(start..start + 32)?.try_into().ok() };
    let node = CacheNodeIdV1::from_bytes(bytes.get(16..32)?.try_into().ok()?).ok()?;
    let backing = ProtectedBackingIdentityV1::new(
        ObjectDigest::from_bytes(array(32)?),
        ObjectDigest::from_bytes(array(64)?),
        ObjectDigest::from_bytes(array(96)?),
        ObjectDigest::from_bytes(array(128)?),
    )
    .ok()?;
    let kind = match bytes[160] {
        1 => CacheDomainKind::Private,
        2 => CacheDomainKind::Project,
        3 => CacheDomainKind::TrustDomain,
        4 => CacheDomainKind::Public,
        _ => return None,
    };
    let disclosure = CacheDomain::new(
        kind,
        CacheDomainId::from_bytes(bytes.get(161..177)?.try_into().ok()?),
    );
    let partition = PhysicalPartitionId::derive(
        node,
        backing,
        disclosure,
        ObjectDigest::from_bytes(array(177)?),
    )
    .ok()?;
    if partition.digest().as_bytes() != bytes.get(209..241)? {
        return None;
    }
    Some(partition)
}

fn cache_record_kind_matches(
    protected: CacheResidencyProtectedRecordKindV1,
    durable: CacheRecordKindV1,
) -> bool {
    match protected {
        CacheResidencyProtectedRecordKindV1::Authority => matches!(
            durable,
            CacheRecordKindV1::Domain | CacheRecordKindV1::ReadHandoff
        ),
        CacheResidencyProtectedRecordKindV1::GlobalAccounting
        | CacheResidencyProtectedRecordKindV1::ProjectAccounting
        | CacheResidencyProtectedRecordKindV1::DomainAccounting => {
            matches!(durable, CacheRecordKindV1::Quota | CacheRecordKindV1::Pin)
        }
        CacheResidencyProtectedRecordKindV1::Reservation => {
            durable == CacheRecordKindV1::Reservation
        }
        CacheResidencyProtectedRecordKindV1::Pin => durable == CacheRecordKindV1::Pin,
        CacheResidencyProtectedRecordKindV1::Scrub => durable == CacheRecordKindV1::Scrub,
        CacheResidencyProtectedRecordKindV1::Eviction => matches!(
            durable,
            CacheRecordKindV1::EvictionPlan | CacheRecordKindV1::EvictionProgress
        ),
        CacheResidencyProtectedRecordKindV1::Catalog => durable == CacheRecordKindV1::Catalog,
        CacheResidencyProtectedRecordKindV1::Effect => matches!(
            durable,
            CacheRecordKindV1::Admission
                | CacheRecordKindV1::EvictionPlan
                | CacheRecordKindV1::ReadHandoff
        ),
        CacheResidencyProtectedRecordKindV1::Current => {
            !matches!(durable, CacheRecordKindV1::Poison)
        }
        CacheResidencyProtectedRecordKindV1::Checkpoint => false,
        CacheResidencyProtectedRecordKindV1::EffectObservation => false,
    }
}

fn classify_replayed_cache_transaction(
    records: &[CacheResidencyProtectedJournalEnvelopeV1],
) -> Result<CacheResidencyTransactionKindV1, CacheResidencyProtectedJournalErrorV1> {
    use CacheResidencyProtectedRecordKindV1 as Record;
    if records.len() == 1 && records[0].key().kind() == Record::Checkpoint {
        return Ok(CacheResidencyTransactionKindV1::Checkpoint);
    }
    if records.len() == 1 && records[0].key().kind() == Record::EffectObservation {
        return Ok(CacheResidencyTransactionKindV1::Recovery);
    }
    let has = |kind| records.iter().any(|record| record.key().kind() == kind);
    if has(Record::Reservation) && has(Record::Effect) {
        Ok(CacheResidencyTransactionKindV1::Admission)
    } else if has(Record::Eviction) && has(Record::Effect) {
        Ok(CacheResidencyTransactionKindV1::EvictionPrepare)
    } else if has(Record::Eviction) && has(Record::Current) {
        Ok(CacheResidencyTransactionKindV1::EvictionFinalize)
    } else if has(Record::Scrub) {
        Ok(CacheResidencyTransactionKindV1::Scrub)
    } else if has(Record::Pin) && has(Record::Current) {
        Ok(CacheResidencyTransactionKindV1::PinChange)
    } else if has(Record::Authority) && has(Record::Current) {
        Ok(CacheResidencyTransactionKindV1::Recovery)
    } else {
        Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)
    }
}

fn validate_cache_key(
    key: &CacheResidencyProtectedJournalKeyV1,
) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
    let identity = key.identity();
    if key.kind() == CacheResidencyProtectedRecordKindV1::EffectObservation {
        return if identity.len() == 16 && identity != [0; 16] {
            Ok(())
        } else {
            Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)
        };
    }
    if !cache_identity_length_matches(key.kind(), identity.len())
        || identity[..32] == [0; 32]
        || identity[49..81] == [0; 32]
        || (identity.len() == 121 && (identity[81..89] == [0; 8] || identity[89..121] == [0; 32]))
    {
        return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
    }
    let valid_scope = match key.kind() {
        CacheResidencyProtectedRecordKindV1::ProjectAccounting => {
            identity[32] == 1 && identity[33..49] != [0; 16]
        }
        CacheResidencyProtectedRecordKindV1::DomainAccounting => {
            identity[32] == 2 && identity[33..49] != [0; 16]
        }
        _ => identity[32] == 0 && identity[33..49] == [0; 16],
    };
    if !valid_scope {
        return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
    }
    Ok(())
}
