//! Fixed-path ownership for dormant cache-residency durability.
//!
//! The owner opens three independent owner-checked journals: cache state, cache
//! authority manifests, and a monotone wall-clock floor. Authority manifests
//! carry the complete checkpoint/floor evidence needed for cold replay. The
//! clock journal prevents a copied or expired manifest from becoming current
//! merely because a process restarted or the wall clock moved backwards.

use std::{
    fs, io,
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use aos_sandbox_core::model::CacheDomainKind;
use aos_sandbox_core::{
    AttachmentId, ObjectDescriptor, ObjectDigest, OperationId, ProjectId, ViewId,
};
use sha2::{Digest as _, Sha256};

use crate::journal::{
    CACHE_POLICY_HOLD_JOURNAL, CachePolicyHoldV1, Journal, JournalLimits, JournalRecord,
    JournalTransaction, RecordNamespace, RecoveryReport,
};
use crate::lifecycle::protected_journal_adapter::ProtectedDomainJournalErrorV1;

use super::protected_journal::{
    CacheResidencyCurrentTimeAuthorityV1, CacheResidencyReplayPartitionEvidenceV1,
    ProtectedCacheResidencyReplayAuthorityV1, decode_partition_descriptor,
    encode_partition_descriptor, reconstruct_cache_history,
    replay_closed_policy_historical_inventories,
};
use super::{
    CacheAtomicObjectPayloadV1, CacheAuthorityOwner, CacheAuthorityPurposeV1,
    CacheAuthorityScopeV1, CachePinV1, CacheRecoveryInventoryV1, CacheRecoveryLimitsV1,
    CacheResidencyAuthorityRequestV1, CacheResidencyColdRecoveryV1, CacheResidencyCommitOutcomeV1,
    CacheResidencyControllerRecordV1, CacheResidencyOutcomeUnknownV1,
    CacheResidencyProtectedJournalEnvelopeV1, CacheResidencyProtectedJournalErrorV1,
    CacheResidencyProtectedJournalProjectionV1, CacheResidencyProtectedJournalSnapshotV1,
    CacheResidencyProtectedJournalV1, CacheResidencyProtectedRecordKindV1,
    CacheResidencyRecoveryV1, CacheResidencyReplayValidatorV1, CacheResidencyTransactionKindV1,
    CacheScrubRecordV1, CacheTypedCheckpointV1, EvictionProgressV1, EvictionRetryAuthorityV1,
    FrozenEvictionPlanV1, PhysicalPartitionId, ReclamationEvidenceV1, ReleasedCachePinV1,
    UnlinkObservationV1, ValidatedCacheResidencyPostcommitV1, VerifiedCacheCapabilityV1,
    cache_residency_protected_key_v1, cache_residency_reducer_envelope_v1, decode_floor,
    decode_typed_checkpoint, encode_floor,
};

mod pin_lookup;
mod provisioning;
mod root_read_only;

pub use pin_lookup::PublicLogicalPinAcquisitionCommitV1;
pub(crate) use provisioning::validate_genesis_checkpoint;
pub use root_read_only::{
    CacheResidencyRootReadOnlyReplayV1, replay_fixed_root_read_only_cache_journals_v1,
};

// A sibling of the object root keeps the live journal directory beneath a
// root-owned parent. An idmapped directory view then follows compaction renames
// without disclosing object storage or allowing the Controller to replace the
// mounted directory name.
const PROTECTED_CACHE_ROOT: &str = "/var/lib/aos/sandbox/cache-residency-journals";
const LEGACY_CACHE_ROOT: &str = "/var/lib/aos/sandbox/cache-residency";
const CACHE_STATE_JOURNAL: &str = "state.journal";
const CACHE_AUTHORITY_JOURNAL: &str = "authority.journal";
const CACHE_CLOCK_JOURNAL: &str = "clock.journal";
const CACHE_CLOCK_KEY: &[u8] = b"\0aos-cache-residency-clock-v1\0current";
pub(super) const CACHE_MANIFEST_KEY_PREFIX: &[u8] = b"\0aos-cache-replay-manifest-v1\0";
const CACHE_MANIFEST_MAGIC: &[u8; 8] = b"AOSCRM01";
const CACHE_CLOCK_MAGIC: &[u8; 8] = b"AOSCCL01";
const CACHE_CLOCK_BYTES: usize = 104;
const CACHE_MANIFEST_FIXED_BYTES: usize = 555;
pub(super) const MAXIMUM_CACHE_MANIFESTS: usize = 4_096;
const MAXIMUM_AUTHORITY_RECORD_BYTES: usize = 1024 * 1024;

fn open_cache_journal(
    root: &Path,
    name: &str,
    limits: JournalLimits,
    owner_uid: u32,
) -> Result<(Journal, RecoveryReport), crate::journal::JournalError> {
    reject_legacy_cache_journals()?;
    Journal::initialize_cache_policy_hold_at(root, owner_uid)?;
    #[cfg(test)]
    let opened = if root == Path::new(PROTECTED_CACHE_ROOT) {
        Journal::open_protected_at_for_uid(root, name, limits, owner_uid)
    } else {
        Journal::open_protected_at_uid(root, name, limits, owner_uid)
    };
    #[cfg(not(test))]
    let opened = Journal::open_protected_at_for_uid(root, name, limits, owner_uid);
    let (mut journal, report) = opened?;
    if matches!(name, CACHE_STATE_JOURNAL | CACHE_AUTHORITY_JOURNAL) {
        journal.enable_cache_policy_hold_gate(root, owner_uid)?;
    }
    Ok((journal, report))
}

fn reject_legacy_cache_journals() -> Result<(), crate::journal::JournalError> {
    reject_legacy_cache_journals_at(Path::new(LEGACY_CACHE_ROOT))
}

fn reject_legacy_cache_journals_at(root: &Path) -> Result<(), crate::journal::JournalError> {
    for name in [
        CACHE_STATE_JOURNAL,
        CACHE_AUTHORITY_JOURNAL,
        CACHE_CLOCK_JOURNAL,
        CACHE_POLICY_HOLD_JOURNAL,
    ] {
        for suffix in ["", ".lock", ".compact.tmp"] {
            let legacy = root.join(format!("{name}{suffix}"));
            match fs::symlink_metadata(legacy) {
                Ok(_) => return Err(crate::journal::JournalError::ProtectedBoundary),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(crate::journal::JournalError::Io(error)),
            }
        }
    }
    Ok(())
}

/// Reports the three protected journal replays performed by the fixed owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheResidencyProtectedOpenReportV1 {
    /// Reports cache state replay.
    pub state: RecoveryReport,
    /// Reports cache authority-manifest replay.
    pub authority: RecoveryReport,
    /// Reports monotone clock-floor replay.
    pub clock: RecoveryReport,
}

/// Owns the complete dormant cache-residency protected boundary.
///
/// No raw [`Journal`], [`CacheAuthorityOwner`], or replay validator escapes
/// this type. Planning and commit occur beneath one adapter claim so prepared
/// authority cannot be substituted between calls.
pub struct CacheResidencyProtectedOwnerV1 {
    state_journal: Option<Journal>,
    authority: Arc<ProtectedCacheResidencyReplayAuthorityV1>,
    owner_uid: u32,
}

/// Identifies one unambiguous project partition from complete protected Cache replay.
///
/// This is a source observation, not effect or policy-publication authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CurrentProjectPhysicalCacheHeadV1 {
    project: ProjectId,
    partition: PhysicalPartitionId,
    head: ObjectDigest,
}

impl CurrentProjectPhysicalCacheHeadV1 {
    /// Returns the project whose physical disclosure and quota were checked.
    #[must_use]
    pub(crate) const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the uniquely selected physical partition.
    #[must_use]
    pub(crate) const fn partition(self) -> PhysicalPartitionId {
        self.partition
    }

    /// Returns the exact protected Cache inventory and replay-authority commitment.
    #[must_use]
    pub(crate) const fn head(self) -> ObjectDigest {
        self.head
    }
}

fn unique_project_physical_cache_head(
    candidates: impl IntoIterator<Item = CurrentProjectPhysicalCacheHeadV1>,
) -> Result<CurrentProjectPhysicalCacheHeadV1, CacheResidencyProtectedJournalErrorV1> {
    let mut candidates = candidates.into_iter();
    let head = candidates
        .next()
        .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
    if candidates.next().is_some() {
        return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
    }
    Ok(head)
}

fn select_project_physical_cache_head(
    project: ProjectId,
    inventories: Vec<CacheRecoveryInventoryV1>,
) -> Result<CurrentProjectPhysicalCacheHeadV1, CacheResidencyProtectedJournalErrorV1> {
    let mut candidates = Vec::new();
    for inventory in inventories {
        let partition = inventory.global.node_quota.partition;
        let disclosure = partition.disclosure();
        if disclosure.kind() != CacheDomainKind::Project
            || disclosure.domain_id().as_bytes() != project.as_bytes()
        {
            continue;
        }
        if inventory.authority_poisoned
            || inventory.global.poison.is_some()
            || !inventory.work.is_empty()
            || inventory
                .global
                .project_quotas
                .iter()
                .filter(|quota| quota.project == project && quota.partition == partition)
                .count()
                != 1
        {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }

        let head = project_physical_cache_head_digest(
            project,
            partition,
            inventory.protected_replay_binding(),
        );
        candidates.push(CurrentProjectPhysicalCacheHeadV1 {
            project,
            partition,
            head,
        });
    }
    unique_project_physical_cache_head(candidates)
}

fn project_physical_cache_head_digest(
    project: ProjectId,
    partition: PhysicalPartitionId,
    replay_binding: ObjectDigest,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.cache.project-physical-head.v1\0")
            .chain_update(project.as_bytes())
            .chain_update(partition.digest().as_bytes())
            .chain_update(replay_binding.as_bytes())
            .finalize()
            .into(),
    )
}

/// Carries one complete protected Cache currentness root and its actionable resources.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CacheLifecycleBootInventoryV1 {
    root: ObjectDigest,
    entries: Vec<crate::lifecycle::LifecycleBootDomainEntryV1>,
}

impl CacheLifecycleBootInventoryV1 {
    pub(crate) const fn root(&self) -> ObjectDigest {
        self.root
    }

    pub(crate) fn entries(&self) -> &[crate::lifecycle::LifecycleBootDomainEntryV1] {
        &self.entries
    }
}

/// Classifies cold cache resolution without leaking instance-bound authority.
#[must_use = "cold cache resolution must be handled"]
pub enum CacheResidencyProtectedColdOutcomeV1<R> {
    /// The transaction carries no current effect or publication authority.
    StateOnly,
    /// A pending effect requires a separately authenticated physical observation.
    ObservationRequired,
    /// The exact observation successor reached the cache journal.
    ObservationCommitted(CacheResidencyCommitOutcomeV1),
    /// A terminal transaction was revalidated inside the supplied callback.
    Terminal(R),
}

/// Retains exact recovery custody across reopen and authority failures.
#[must_use = "protected recovery must be classified or retried"]
pub enum CacheResidencyProtectedOwnerRecoveryV1<R> {
    /// Protected reopen or preflight failed before consuming the opaque token.
    Pending {
        /// Durable identity for a later cold lookup if the process restarts.
        transaction_id: [u8; 16],
        /// Exact ambiguous transaction for another recovery pass.
        pending: CacheResidencyOutcomeUnknownV1,
        /// Reopen or authority failure.
        cause: CacheResidencyProtectedJournalErrorV1,
    },
    /// The token was classified, with any final authority failure still visible.
    Classified {
        /// Durable identity for revalidation when no handoff was returned.
        transaction_id: [u8; 16],
        /// Exact applied, retry, diverged, or indeterminate result.
        recovery: CacheResidencyRecoveryV1,
        /// Physical handoff result, if current postcommit reached the callback.
        handoff: Option<R>,
        /// Final currentness failed after classification or handoff.
        authority_error: Option<CacheResidencyProtectedJournalErrorV1>,
    },
    /// An internal classification handoff could not return its opaque value.
    /// The stable transaction identity is the only permitted cold fallback.
    ColdLookupRequired {
        /// Durable transaction identity supplied by the caller.
        transaction_id: [u8; 16],
        /// Failure that prevented exact in-process classification.
        cause: CacheResidencyProtectedJournalErrorV1,
    },
}

/// Classifies an exact cold pin change against current protected and owner state.
#[cfg(target_os = "linux")]
#[must_use = "cold pin recovery must be settled or retried"]
pub enum CacheResidencyProtectedPinRecoveryV1 {
    /// No complete current pin effect exists for this transaction identity.
    StateOnly,
    /// The exact physical pin was reconciled or was already in its desired state.
    Settled(super::CacheOwnerPinReconciliationV1),
    /// The current protected effect exists, but the physical owner rejected it.
    PhysicalError(super::CacheOwnerPinSettlementErrorV1),
}

/// Borrows exact cache authority for one fixed-owner controller construction.
pub struct CacheResidencyAuthorizedControllerV1<'session, 'authority, 'journal> {
    owner: &'session CacheAuthorityOwner<'authority, 'journal>,
    capabilities: &'session [VerifiedCacheCapabilityV1],
    transaction_kind: CacheResidencyTransactionKindV1,
    now: u64,
}

/// Carries one canonical payload authorized by exact typed domain evidence.
///
/// Only purpose-specific methods on [`CacheResidencyAuthorizedControllerV1`]
/// can construct this value. It is consumed when one journal member is sealed.
pub struct CacheResidencyAuthorizedPayloadV1<'session> {
    payload: CacheAtomicObjectPayloadV1,
    payload_digest: ObjectDigest,
    capability_index: usize,
    purpose: CacheAuthorityPurposeV1,
    scope: CacheAuthorityScopeV1,
    prerequisites: Vec<CacheResidencyAuthorizedPrerequisiteV1>,
    transaction_kind: CacheResidencyTransactionKindV1,
    session: std::marker::PhantomData<&'session ()>,
}

struct CacheResidencyAuthorizedPrerequisiteV1 {
    capability_index: usize,
    purpose: CacheAuthorityPurposeV1,
    scope: CacheAuthorityScopeV1,
}

impl<'session, 'authority, 'journal>
    CacheResidencyAuthorizedControllerV1<'session, 'authority, 'journal>
{
    /// Returns the sealed authority owner needed by typed domain constructors.
    #[must_use]
    pub const fn owner(&self) -> &CacheAuthorityOwner<'authority, 'journal> {
        self.owner
    }

    /// Returns one selected capability by request order.
    #[must_use]
    pub fn capability(&self, index: usize) -> Option<&VerifiedCacheCapabilityV1> {
        self.capabilities.get(index)
    }

    /// Returns the fresh protected time for typed domain constructors.
    #[must_use]
    pub const fn current_unix_seconds(&self) -> u64 {
        self.now
    }

    /// Authorizes an initial admission payload against its complete immutable plan scope.
    pub fn authorize_initial_admission_payload(
        &self,
        payload: CacheAtomicObjectPayloadV1,
        capability: usize,
    ) -> Option<CacheResidencyAuthorizedPayloadV1<'session>> {
        let scope = payload.plan.authority_scope().ok()?;
        let record_digest = self.capabilities.get(capability)?.record_digest();
        let (source_scope, source_record) = payload
            .plan
            .source
            .authority_binding(payload.plan.partition)
            .ok()?;
        let (source_index, source_capability) =
            self.capabilities
                .iter()
                .enumerate()
                .find(|(_, candidate)| {
                    candidate.purpose() == CacheAuthorityPurposeV1::Source
                        && candidate.record_digest() == source_record
                })?;
        self.owner
            .validate_for_effect_at(
                source_capability,
                CacheAuthorityPurposeV1::Source,
                source_scope,
                self.now,
            )
            .ok()?;
        if payload.progress.generation != 1
            || payload.progress.predecessor.is_some()
            || payload.progress.evidence != record_digest
        {
            return None;
        }
        let mut authorized = self.authorize_payload(
            payload,
            capability,
            CacheAuthorityPurposeV1::Admission,
            scope,
        )?;
        authorized
            .prerequisites
            .push(CacheResidencyAuthorizedPrerequisiteV1 {
                capability_index: source_index,
                purpose: CacheAuthorityPurposeV1::Source,
                scope: source_scope,
            });
        Some(authorized)
    }

    /// Authorizes a pin-acquisition payload against the exact embedded pin.
    pub fn authorize_pin_acquisition_payload(
        &self,
        payload: CacheAtomicObjectPayloadV1,
        capability: usize,
        pin: &CachePinV1,
    ) -> Option<CacheResidencyAuthorizedPayloadV1<'session>> {
        let (scope, record_digest) = pin.authority_binding();
        if !payload.pins.iter().any(|candidate| candidate == pin)
            || self.capabilities.get(capability)?.record_digest() != record_digest
        {
            return None;
        }
        self.authorize_payload(
            payload,
            capability,
            CacheAuthorityPurposeV1::PinAcquire,
            scope,
        )
    }

    /// Authorizes a pin-release payload against the exact embedded tombstone.
    pub fn authorize_pin_release_payload(
        &self,
        payload: CacheAtomicObjectPayloadV1,
        capability: usize,
        released: &ReleasedCachePinV1,
    ) -> Option<CacheResidencyAuthorizedPayloadV1<'session>> {
        let (scope, record_digest) = released.drain.authority_binding();
        if !payload
            .released_pins
            .iter()
            .any(|candidate| candidate == released)
            || self.capabilities.get(capability)?.record_digest() != record_digest
        {
            return None;
        }
        self.authorize_payload(
            payload,
            capability,
            CacheAuthorityPurposeV1::PinDrain,
            scope,
        )
    }

    /// Seals one logical acquisition or renewal as a single durable Pin event.
    ///
    /// The selected PinAcquire record must have been issued only after current
    /// View source membership and consumer authority were independently proved.
    /// This constructor does not infer those facts from a public request.
    ///
    /// # Errors
    ///
    /// Returns an error for stale acquisition authority, inconsistent retained
    /// ledger state, invalid projections, or an unsealable successor.
    pub fn seal_logical_pin_acquisition(
        &self,
        inventory: &CacheRecoveryInventoryV1,
        pin: CachePinV1,
        operation: OperationId,
    ) -> Result<
        Vec<CacheResidencyControllerRecordV1<'session>>,
        CacheResidencyProtectedJournalErrorV1,
    > {
        let capability = self
            .capability(0)
            .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
        let payload = inventory
            .plan_logical_pin_acquisition(
                self.owner,
                capability,
                pin.clone(),
                operation,
                self.now,
                CacheRecoveryLimitsV1::default(),
            )
            .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
        let authorize = || {
            self.authorize_pin_acquisition_payload(payload.clone(), 0, &pin)
                .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)
        };
        Ok(vec![
            self.seal_pin(authorize()?)
                .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?,
            self.seal_global_accounting(authorize()?)
                .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?,
            self.seal_project_accounting(authorize()?)
                .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?,
            self.seal_domain_accounting(authorize()?)
                .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?,
            self.seal_current(authorize()?)
                .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?,
        ])
    }

    /// Seals one logical release as five aliases of the same durable Pin event.
    ///
    /// # Errors
    ///
    /// Returns an error when retained state, drain authority, projections, or
    /// the exact payload-to-capability binding cannot be validated.
    pub fn seal_logical_pin_release(
        &self,
        inventory: &CacheRecoveryInventoryV1,
        pin: &CachePinV1,
        operation: OperationId,
    ) -> Result<
        Vec<CacheResidencyControllerRecordV1<'session>>,
        CacheResidencyProtectedJournalErrorV1,
    > {
        let capability = self
            .capability(0)
            .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
        let valid_until = capability.scope().valid_until();
        let (payload, released) = inventory
            .plan_logical_pin_release(
                self.owner,
                capability,
                pin,
                operation,
                valid_until,
                self.now,
                CacheRecoveryLimitsV1::default(),
            )
            .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
        let authorize = || {
            self.authorize_pin_release_payload(payload.clone(), 0, &released)
                .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)
        };
        Ok(vec![
            self.seal_pin(authorize()?)
                .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?,
            self.seal_global_accounting(authorize()?)
                .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?,
            self.seal_project_accounting(authorize()?)
                .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?,
            self.seal_domain_accounting(authorize()?)
                .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?,
            self.seal_current(authorize()?)
                .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?,
        ])
    }

    /// Authorizes a scrub payload against its exact verifier-issued observation.
    pub fn authorize_scrub_payload(
        &self,
        payload: CacheAtomicObjectPayloadV1,
        capability: usize,
        scrub: &CacheScrubRecordV1,
    ) -> Option<CacheResidencyAuthorizedPayloadV1<'session>> {
        let (scope, record_digest) = scrub.evidence.authority_binding();
        if payload.scrub.as_ref() != Some(scrub)
            || self.capabilities.get(capability)?.record_digest() != record_digest
        {
            return None;
        }
        self.authorize_payload(payload, capability, CacheAuthorityPurposeV1::Scrub, scope)
    }

    /// Authorizes eviction preparation against its exact frozen candidate plan.
    pub fn authorize_eviction_plan_payload(
        &self,
        payload: CacheAtomicObjectPayloadV1,
        capability: usize,
        plan: &FrozenEvictionPlanV1,
    ) -> Option<CacheResidencyAuthorizedPayloadV1<'session>> {
        let (scope, record_digest) = plan.authority_binding();
        if payload.eviction_plan.as_ref() != Some(plan)
            || self.capabilities.get(capability)?.record_digest() != record_digest
        {
            return None;
        }
        self.authorize_payload(
            payload,
            capability,
            CacheAuthorityPurposeV1::Eviction,
            scope,
        )
    }

    /// Authorizes an unlink-result payload against verifier-issued observation evidence.
    pub fn authorize_unlink_observation_payload(
        &self,
        payload: CacheAtomicObjectPayloadV1,
        capability: usize,
        plan: &FrozenEvictionPlanV1,
        previous: &EvictionProgressV1,
        observation: &UnlinkObservationV1,
    ) -> Option<CacheResidencyAuthorizedPayloadV1<'session>> {
        let selected = self.capabilities.get(capability)?;
        observation
            .validate_current(self.owner, selected, plan, previous, self.now)
            .ok()?;
        let (scope, _record_digest) = observation.authority_binding();
        if payload.eviction_plan.as_ref() != Some(plan)
            || !payload
                .eviction_progress
                .iter()
                .any(|next| observation.matches_successor(previous, next, payload.catalog.as_ref()))
        {
            return None;
        }
        self.authorize_payload(
            payload,
            capability,
            CacheAuthorityPurposeV1::UnlinkObservation,
            scope,
        )
    }

    /// Authorizes a reclaimed-byte payload against verifier-issued physical evidence.
    pub fn authorize_reclamation_payload(
        &self,
        payload: CacheAtomicObjectPayloadV1,
        capability: usize,
        plan: &FrozenEvictionPlanV1,
        previous: &EvictionProgressV1,
        evidence: ReclamationEvidenceV1,
    ) -> Option<CacheResidencyAuthorizedPayloadV1<'session>> {
        let selected = self.capabilities.get(capability)?;
        evidence
            .validate_current(self.owner, selected, plan, previous, self.now)
            .ok()?;
        let (scope, _record_digest) = evidence.authority_binding();
        if payload.eviction_plan.as_ref() != Some(plan)
            || !payload
                .eviction_progress
                .iter()
                .any(|next| evidence.matches_successor(previous, next, payload.catalog.as_ref()))
        {
            return None;
        }
        self.authorize_payload(
            payload,
            capability,
            CacheAuthorityPurposeV1::Reclamation,
            scope,
        )
    }

    /// Authorizes an ambiguity retry payload against a fenced, re-observed attempt.
    pub fn authorize_eviction_retry_payload(
        &self,
        payload: CacheAtomicObjectPayloadV1,
        retry_capability: usize,
        plan: &FrozenEvictionPlanV1,
        previous: &EvictionProgressV1,
        observation: &UnlinkObservationV1,
        retry: EvictionRetryAuthorityV1,
    ) -> Option<CacheResidencyAuthorizedPayloadV1<'session>> {
        let selected = self.capabilities.get(retry_capability)?;
        retry
            .validate_current(self.owner, selected, plan, previous, self.now)
            .ok()?;
        let (observation_scope, observation_record) = observation.authority_binding();
        let (observation_index, observation_capability) = self
            .capabilities
            .iter()
            .enumerate()
            .find(|(_, candidate)| {
                candidate.purpose() == CacheAuthorityPurposeV1::UnlinkObservation
                    && candidate.record_digest() == observation_record
            })?;
        observation
            .validate_current(self.owner, observation_capability, plan, previous, self.now)
            .ok()?;
        if payload.eviction_plan.as_ref() != Some(plan)
            || !payload.eviction_progress.iter().any(|next| {
                retry.matches_observation_and_successor(
                    observation,
                    previous,
                    next,
                    payload.catalog.as_ref(),
                )
            })
        {
            return None;
        }
        let mut authorized = self.authorize_payload(
            payload,
            observation_index,
            CacheAuthorityPurposeV1::UnlinkObservation,
            observation_scope,
        )?;
        authorized
            .prerequisites
            .push(CacheResidencyAuthorizedPrerequisiteV1 {
                capability_index: retry_capability,
                purpose: CacheAuthorityPurposeV1::Retry,
                scope: selected.scope(),
            });
        Some(authorized)
    }

    /// Seals an authority record against one selected capability.
    pub fn seal_authority(
        &self,
        authorized: CacheResidencyAuthorizedPayloadV1<'session>,
    ) -> Option<CacheResidencyControllerRecordV1<'session>> {
        self.seal(CacheResidencyProtectedRecordKindV1::Authority, authorized)
    }

    /// Seals a global-accounting record against one selected capability.
    pub fn seal_global_accounting(
        &self,
        authorized: CacheResidencyAuthorizedPayloadV1<'session>,
    ) -> Option<CacheResidencyControllerRecordV1<'session>> {
        self.seal(
            CacheResidencyProtectedRecordKindV1::GlobalAccounting,
            authorized,
        )
    }

    /// Seals a project-accounting record against one selected capability.
    pub fn seal_project_accounting(
        &self,
        authorized: CacheResidencyAuthorizedPayloadV1<'session>,
    ) -> Option<CacheResidencyControllerRecordV1<'session>> {
        self.seal(
            CacheResidencyProtectedRecordKindV1::ProjectAccounting,
            authorized,
        )
    }

    /// Seals a domain-accounting record against one selected capability.
    pub fn seal_domain_accounting(
        &self,
        authorized: CacheResidencyAuthorizedPayloadV1<'session>,
    ) -> Option<CacheResidencyControllerRecordV1<'session>> {
        self.seal(
            CacheResidencyProtectedRecordKindV1::DomainAccounting,
            authorized,
        )
    }

    /// Seals a reservation record against one selected capability.
    pub fn seal_reservation(
        &self,
        authorized: CacheResidencyAuthorizedPayloadV1<'session>,
    ) -> Option<CacheResidencyControllerRecordV1<'session>> {
        self.seal(CacheResidencyProtectedRecordKindV1::Reservation, authorized)
    }

    /// Seals a pin record against one selected capability.
    pub fn seal_pin(
        &self,
        authorized: CacheResidencyAuthorizedPayloadV1<'session>,
    ) -> Option<CacheResidencyControllerRecordV1<'session>> {
        self.seal(CacheResidencyProtectedRecordKindV1::Pin, authorized)
    }

    /// Seals a scrub record against one selected capability.
    pub fn seal_scrub(
        &self,
        authorized: CacheResidencyAuthorizedPayloadV1<'session>,
    ) -> Option<CacheResidencyControllerRecordV1<'session>> {
        self.seal(CacheResidencyProtectedRecordKindV1::Scrub, authorized)
    }

    /// Seals an eviction record against one selected capability.
    pub fn seal_eviction(
        &self,
        authorized: CacheResidencyAuthorizedPayloadV1<'session>,
    ) -> Option<CacheResidencyControllerRecordV1<'session>> {
        self.seal(CacheResidencyProtectedRecordKindV1::Eviction, authorized)
    }

    /// Seals a catalog record against one selected capability.
    pub fn seal_catalog(
        &self,
        authorized: CacheResidencyAuthorizedPayloadV1<'session>,
    ) -> Option<CacheResidencyControllerRecordV1<'session>> {
        self.seal(CacheResidencyProtectedRecordKindV1::Catalog, authorized)
    }

    /// Seals an effect record against one selected capability.
    pub fn seal_effect(
        &self,
        authorized: CacheResidencyAuthorizedPayloadV1<'session>,
    ) -> Option<CacheResidencyControllerRecordV1<'session>> {
        self.seal(CacheResidencyProtectedRecordKindV1::Effect, authorized)
    }

    /// Seals a current-state record against one selected capability.
    pub fn seal_current(
        &self,
        authorized: CacheResidencyAuthorizedPayloadV1<'session>,
    ) -> Option<CacheResidencyControllerRecordV1<'session>> {
        self.seal(CacheResidencyProtectedRecordKindV1::Current, authorized)
    }

    fn seal(
        &self,
        kind: CacheResidencyProtectedRecordKindV1,
        authorized: CacheResidencyAuthorizedPayloadV1<'session>,
    ) -> Option<CacheResidencyControllerRecordV1<'session>> {
        if authorized.transaction_kind != self.transaction_kind
            || !capability_may_seal_record(self.transaction_kind, authorized.purpose, kind)
        {
            return None;
        }
        let capability = self.capabilities.get(authorized.capability_index)?;
        self.owner
            .validate_for_effect_at(capability, authorized.purpose, authorized.scope, self.now)
            .ok()?;
        for prerequisite in &authorized.prerequisites {
            let capability = self.capabilities.get(prerequisite.capability_index)?;
            self.owner
                .validate_for_effect_at(
                    capability,
                    prerequisite.purpose,
                    prerequisite.scope,
                    self.now,
                )
                .ok()?;
        }
        let authority_record = capability.record_digest();
        if authorized.payload.record.digest != authorized.payload_digest
            || (authorized.payload.record.authority != authority_record
                && authorized.payload.record.evidence != authority_record)
        {
            return None;
        }
        Some(CacheResidencyControllerRecordV1::from_authority(
            kind,
            authorized.payload,
            authority_record,
        ))
    }

    fn authorize_payload(
        &self,
        payload: CacheAtomicObjectPayloadV1,
        capability_index: usize,
        purpose: CacheAuthorityPurposeV1,
        scope: CacheAuthorityScopeV1,
    ) -> Option<CacheResidencyAuthorizedPayloadV1<'session>> {
        let capability = self.capabilities.get(capability_index)?;
        self.owner
            .validate_for_effect_at(capability, purpose, scope, self.now)
            .ok()?;
        let record_digest = capability.record_digest();
        if payload.record.authority != record_digest && payload.record.evidence != record_digest {
            return None;
        }
        let payload_digest = payload
            .canonical_record_digest(CacheRecoveryLimitsV1::default())
            .ok()?;
        Some(CacheResidencyAuthorizedPayloadV1 {
            payload,
            payload_digest,
            capability_index,
            purpose,
            scope,
            prerequisites: Vec::new(),
            transaction_kind: self.transaction_kind,
            session: std::marker::PhantomData,
        })
    }
}

fn capability_may_seal_record(
    transaction: CacheResidencyTransactionKindV1,
    purpose: CacheAuthorityPurposeV1,
    record: CacheResidencyProtectedRecordKindV1,
) -> bool {
    use CacheAuthorityPurposeV1 as Purpose;
    use CacheResidencyProtectedRecordKindV1 as Record;
    use CacheResidencyTransactionKindV1 as Transaction;

    match transaction {
        Transaction::Admission => match record {
            Record::Pin => purpose == Purpose::PinAcquire,
            Record::Authority
            | Record::GlobalAccounting
            | Record::ProjectAccounting
            | Record::DomainAccounting
            | Record::Reservation
            | Record::Catalog
            | Record::Effect
            | Record::Current => purpose == Purpose::Admission,
            _ => false,
        },
        Transaction::PinChange => {
            matches!(purpose, Purpose::PinAcquire | Purpose::PinDrain)
                && matches!(
                    record,
                    Record::GlobalAccounting
                        | Record::ProjectAccounting
                        | Record::DomainAccounting
                        | Record::Pin
                        | Record::Current
                )
        }
        Transaction::Scrub => {
            purpose == Purpose::Scrub
                && matches!(
                    record,
                    Record::Authority
                        | Record::Pin
                        | Record::Scrub
                        | Record::Catalog
                        | Record::Current
                )
        }
        Transaction::EvictionPrepare => {
            purpose == Purpose::Eviction
                && matches!(
                    record,
                    Record::Authority
                        | Record::Pin
                        | Record::Eviction
                        | Record::Catalog
                        | Record::Effect
                        | Record::Current
                )
        }
        Transaction::EvictionFinalize => {
            matches!(purpose, Purpose::UnlinkObservation | Purpose::Reclamation)
                && matches!(
                    record,
                    Record::GlobalAccounting
                        | Record::ProjectAccounting
                        | Record::DomainAccounting
                        | Record::Pin
                        | Record::Scrub
                        | Record::Eviction
                        | Record::Catalog
                        | Record::Current
                )
        }
        Transaction::Recovery | Transaction::Checkpoint => false,
    }
}

impl CacheResidencyProtectedOwnerV1 {
    /// Opens fixed root-owned journals and cold-replays every cache partition.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe protected path, malformed authority
    /// manifest, stale/expired time, rollback, or invalid cache history.
    pub fn open_fixed_protected()
    -> Result<(Self, CacheResidencyProtectedOpenReportV1), CacheResidencyProtectedJournalErrorV1>
    {
        Self::open_fixed_protected_for_uid(0)
    }

    /// Opens fixed cache journals for the configured service UID.
    ///
    /// The fixed protected journal directory is shared with the root-owned
    /// variant; only the accepted filesystem owner differs.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe ownership, malformed replay, stale time,
    /// rollback, or invalid cache history.
    pub fn open_fixed_protected_for_uid(
        owner_uid: u32,
    ) -> Result<(Self, CacheResidencyProtectedOpenReportV1), CacheResidencyProtectedJournalErrorV1>
    {
        let root = Path::new(PROTECTED_CACHE_ROOT);
        let owner_scope = cache_owner_scope();
        let (clock, clock_report) = ProtectedCacheClockV1::open(root, owner_scope, owner_uid)?;
        let clock: Arc<dyn CacheResidencyCurrentTimeAuthorityV1> = Arc::new(clock);

        let (mut authority_journal, authority_report) = open_cache_journal(
            root,
            CACHE_AUTHORITY_JOURNAL,
            cache_authority_journal_limits(),
            owner_uid,
        )?;
        let evidence = recover_cache_replay_evidence(
            &mut authority_journal,
            owner_scope,
            CacheRecoveryLimitsV1::default(),
        )?;
        let (_validator, authority) = CacheResidencyReplayValidatorV1::from_protected_authority(
            authority_journal,
            owner_scope,
            MAXIMUM_AUTHORITY_RECORD_BYTES,
            evidence,
            CacheRecoveryLimitsV1::default(),
            clock,
        )?;

        let (state_journal, state_report) = open_cache_journal(
            root,
            CACHE_STATE_JOURNAL,
            cache_state_journal_limits(),
            owner_uid,
        )?;
        let mut owner = Self {
            state_journal: Some(state_journal),
            authority,
            owner_uid,
        };
        owner.replay()?;

        Ok((
            owner,
            CacheResidencyProtectedOpenReportV1 {
                state: state_report,
                authority: authority_report,
                clock: clock_report,
            },
        ))
    }

    /// Replays the complete cache projection under fresh protected time.
    ///
    /// # Errors
    ///
    /// Returns an error when protected storage, time, or typed cache history is
    /// no longer current and canonical.
    pub fn replay(
        &mut self,
    ) -> Result<CacheResidencyProtectedJournalProjectionV1, CacheResidencyProtectedJournalErrorV1>
    {
        let authority = Arc::clone(&self.authority);
        authority.while_authority_current(&[], |_owner, _capabilities, _now, validator, refresh| {
            let journal = self
                .state_journal
                .as_mut()
                .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            let projection =
                CacheResidencyProtectedJournalV1::claim(journal, validator.clone())?.replay()?;
            refresh()?;
            Ok(projection)
        })
    }

    /// Returns every authenticated node quota in the current protected replay.
    ///
    /// A node-global physical owner must derive its bounds from the complete
    /// partition set, not from the partition named by one public request.
    /// This is historical configuration, not pin or publication authority.
    ///
    /// # Errors
    ///
    /// Returns an error when protected time, authority, or full typed replay
    /// cannot be validated at both ends of the observation.
    pub fn reconstructed_node_quotas(
        &mut self,
    ) -> Result<Vec<super::NodeCacheQuotaV1>, CacheResidencyProtectedJournalErrorV1> {
        Ok(self
            .reconstructed_partitions()?
            .into_iter()
            .map(|inventory| inventory.global.node_quota)
            .collect())
    }

    /// Returns every reconstructed partition from one current protected replay.
    ///
    /// This is historical catalog state, not publication or pin authority. A
    /// caller selecting a physical partition must still obtain exact current
    /// pin authority and recheck the public consumer at commit time.
    ///
    /// # Errors
    ///
    /// Returns an error when protected time, authority, or typed replay cannot
    /// be validated at both ends of the observation.
    pub fn reconstructed_partitions(
        &mut self,
    ) -> Result<Vec<CacheRecoveryInventoryV1>, CacheResidencyProtectedJournalErrorV1> {
        self.with_reconstructed_partitions(Ok)
    }

    /// Runs one action while a unique, healthy project partition stays custodied.
    ///
    /// The complete protected Cache state, replay authority, and clock floor
    /// remain held through the callback and are refreshed afterward. A policy
    /// issuer must also hold the controller, source-domain, and root owners
    /// through its binding CAS and effect handoff; this callback alone does not
    /// authorize AOSPCB01 publication.
    ///
    /// # Errors
    ///
    /// Fails closed for absent or ambiguous project partitions, missing
    /// project quota, poison, unresolved recovery work, or invalid replay.
    pub(crate) fn while_current_project_physical_cache<R>(
        &mut self,
        project: ProjectId,
        action: impl FnOnce(CurrentProjectPhysicalCacheHeadV1) -> R,
    ) -> Result<R, CacheResidencyProtectedJournalErrorV1> {
        if project.as_bytes() == &[0; 16] {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }

        self.with_reconstructed_partitions(|inventories| {
            let selected = select_project_physical_cache_head(project, inventories)?;
            Ok(action(selected))
        })
    }

    /// Freezes the exact project Cache quota, domain, and replay head for a closed binding.
    ///
    /// The owner retains its state and manifest writer locks before acquiring
    /// the hold-journal lock. Every later state or manifest append and
    /// compaction checks that lock, including after a cold reopen. This hold
    /// is inert until another owner independently verifies it under the full
    /// Controller, source-domain, physical Cache, and root cut.
    ///
    /// # Errors
    ///
    /// Rejects a stale or ambiguous partition, a different protected head,
    /// existing held custody, or a failed durable hold write/readback.
    pub fn acquire_closed_policy_hold_v1(
        &mut self,
        project: ProjectId,
        expected_partition: ObjectDigest,
        expected_head: ObjectDigest,
        binding: ObjectDigest,
        epoch: u64,
    ) -> Result<CachePolicyHoldV1, CacheResidencyProtectedJournalErrorV1> {
        let current = self.while_current_project_physical_cache(project, |head| head)?;
        if current.partition().digest() != expected_partition || current.head() != expected_head {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        let hold =
            CachePolicyHoldV1::new(project, expected_partition, expected_head, binding, epoch)?;
        Journal::acquire_cache_policy_hold_at(
            Path::new(PROTECTED_CACHE_ROOT),
            self.owner_uid,
            hold,
        )?;
        let after = self.while_current_project_physical_cache(project, |head| head)?;
        if after != current {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        Ok(hold)
    }

    /// Reads the exact durable Cache hold under its protected writer.
    ///
    /// This is an observation, not a root binding or effect capability.
    ///
    /// # Errors
    ///
    /// Rejects malformed or unavailable hold custody.
    pub fn closed_policy_hold_v1(
        &self,
    ) -> Result<Option<CachePolicyHoldV1>, CacheResidencyProtectedJournalErrorV1> {
        Ok(Journal::read_cache_policy_hold_at(
            Path::new(PROTECTED_CACHE_ROOT),
            self.owner_uid,
        )?)
    }

    // Keep selection inside the protected claim so its errors retain priority
    // over the final currentness refresh.
    fn with_reconstructed_partitions<R>(
        &mut self,
        select: impl FnOnce(
            Vec<CacheRecoveryInventoryV1>,
        ) -> Result<R, CacheResidencyProtectedJournalErrorV1>,
    ) -> Result<R, CacheResidencyProtectedJournalErrorV1> {
        let authority = Arc::clone(&self.authority);
        authority.while_authority_current(&[], |_owner, _capabilities, _now, validator, refresh| {
            let journal = self
                .state_journal
                .as_mut()
                .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            let projection =
                CacheResidencyProtectedJournalV1::claim(journal, validator.clone())?.replay()?;
            let inventories = reconstruct_cache_history(projection.records(), &validator)?;
            let selected = select(inventories)?;
            refresh()?;
            Ok(selected)
        })
    }

    /// Finds the retained logical pin for one exact consumer and cache object.
    ///
    /// This query returns historical state, not current acquisition or drain
    /// authority. In particular, an attachment replacement does not hide a pin
    /// that still needs an independently authorized release.
    ///
    /// # Errors
    ///
    /// Returns an error if protected time, authority, or cache replay fails.
    pub fn retained_logical_pin(
        &mut self,
        partition: PhysicalPartitionId,
        object: &ObjectDescriptor,
        project: ProjectId,
        view: ViewId,
        attachment: Option<AttachmentId>,
    ) -> Result<Option<CachePinV1>, CacheResidencyProtectedJournalErrorV1> {
        self.with_reconstructed_partitions(|inventories| {
            let mut pin = None;
            for inventory in inventories {
                for payload in inventory.reconstructed {
                    if payload.plan.partition != partition
                        || &payload.plan.descriptor != object
                        || payload.plan.project != project
                    {
                        continue;
                    }
                    for candidate in payload.pins {
                        if candidate.partition != partition
                            || &candidate.object != object
                            || candidate.project != project
                            || candidate.view != view
                            || candidate.attachment != attachment
                            || candidate.kind != super::CachePinKindV1::LogicalLease
                        {
                            continue;
                        }
                        if pin.replace(candidate).is_some() {
                            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord.into());
                        }
                    }
                }
            }
            Ok(pin)
        })
    }

    /// Reads the complete Cache projection and separately classifies physical resources.
    ///
    /// Accounting, effect, current-head, checkpoint, scrub, eviction, and
    /// recovery records remain committed by `root` but never become lifecycle
    /// release targets. Only active reservations, publications, and pins are
    /// emitted as physical rows.
    pub(crate) fn lifecycle_boot_inventory(
        &mut self,
    ) -> Result<CacheLifecycleBootInventoryV1, CacheResidencyProtectedJournalErrorV1> {
        let authority = Arc::clone(&self.authority);
        authority.while_authority_current(&[], |_owner, _capabilities, _now, validator, refresh| {
            let journal = self
                .state_journal
                .as_mut()
                .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            let projection =
                CacheResidencyProtectedJournalV1::claim(journal, validator.clone())?.replay()?;
            let inventories = reconstruct_cache_history(projection.records(), &validator)?;
            let mut entries = Vec::new();
            for inventory in inventories {
                for payload in inventory.reconstructed {
                    if matches!(
                        payload.reservation.state,
                        super::ReservationStateV1::Reserved | super::ReservationStateV1::Uncertain
                    ) {
                        entries.push(
                            crate::lifecycle::LifecycleBootDomainEntryV1::from_protected_cache(
                                crate::lifecycle::LifecycleResourceV1::Capability(
                                    aos_sandbox_core::ResourceId::from_bytes(
                                        *payload.reservation.id.as_bytes(),
                                    ),
                                ),
                                payload.reservation.digest,
                            )
                            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?,
                        );
                    }

                    if let Some(catalog) = payload
                        .catalog
                        .filter(|catalog| catalog.presence != super::CatalogPresenceV1::Evicted)
                    {
                        let mut environment = [0_u8; 16];
                        environment.copy_from_slice(&catalog.descriptor.digest().as_bytes()[..16]);
                        entries.push(
                            crate::lifecycle::LifecycleBootDomainEntryV1::from_protected_cache(
                                crate::lifecycle::LifecycleResourceV1::Environment(
                                    aos_sandbox_core::ResourceId::from_bytes(environment),
                                ),
                                catalog.digest,
                            )
                            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?,
                        );
                    }

                    for pin in payload.pins {
                        let resource = if let Some(attachment) = pin.attachment {
                            crate::lifecycle::LifecycleResourceV1::Attachment(
                                aos_sandbox_core::ResourceId::from_bytes(*attachment.as_bytes()),
                            )
                        } else {
                            crate::lifecycle::LifecycleResourceV1::View(pin.view)
                        };
                        // Physical obligations remain distinct across disclosure partitions.
                        let identity = ObjectDigest::from_bytes(
                            Sha256::new()
                                .chain_update(b"aos.sandbox.lifecycle.cache-pin-physical-row.v2\0")
                                .chain_update(pin.partition.digest().as_bytes())
                                .chain_update(pin.id.as_bytes())
                                .chain_update(pin.object.digest().as_bytes())
                                .chain_update([pin.kind as u8])
                                .finalize()
                                .into(),
                        );
                        entries.push(
                            crate::lifecycle::LifecycleBootDomainEntryV1::from_protected_cache(
                                resource, identity,
                            )
                            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?,
                        );
                    }
                }
            }
            entries.sort_unstable();
            entries.dedup();
            if entries.len() > crate::lifecycle::MAXIMUM_LIFECYCLE_EXPECTATIONS {
                return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
            }
            refresh()?;
            Ok(CacheLifecycleBootInventoryV1 {
                root: projection.root(),
                entries,
            })
        })
    }

    /// Captures exact cache currentness under fresh protected time.
    ///
    /// # Errors
    ///
    /// Returns an error when replay or protected currentness fails.
    pub fn snapshot(
        &mut self,
    ) -> Result<CacheResidencyProtectedJournalSnapshotV1, CacheResidencyProtectedJournalErrorV1>
    {
        let authority = Arc::clone(&self.authority);
        authority.while_authority_current(&[], |_owner, _capabilities, _now, validator, refresh| {
            let journal = self
                .state_journal
                .as_mut()
                .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            let snapshot =
                CacheResidencyProtectedJournalV1::claim(journal, validator)?.snapshot()?;
            refresh()?;
            Ok(snapshot)
        })
    }

    /// Commits initial admission while source, admission, and first-pin authority stay locked.
    ///
    /// # Errors
    ///
    /// Returns an error when authority, typed construction, replay, or commit fails closed.
    pub fn commit_authorized_initial_admission<R>(
        &mut self,
        transaction_id: [u8; 16],
        requests: Vec<CacheResidencyAuthorityRequestV1>,
        build: impl for<'session, 'authority, 'journal> FnOnce(
            &CacheResidencyAuthorizedControllerV1<'session, 'authority, 'journal>,
        ) -> Result<
            Vec<CacheResidencyControllerRecordV1<'session>>,
            CacheResidencyProtectedJournalErrorV1,
        >,
        handoff: impl for<'current> FnOnce(ValidatedCacheResidencyPostcommitV1<'current>) -> R,
    ) -> Result<(CacheResidencyCommitOutcomeV1, Option<R>), CacheResidencyProtectedJournalErrorV1>
    {
        self.commit_authorized_transition(
            transaction_id,
            CacheResidencyTransactionKindV1::Admission,
            &[
                CacheAuthorityPurposeV1::Source,
                CacheAuthorityPurposeV1::Admission,
                CacheAuthorityPurposeV1::PinAcquire,
            ],
            requests,
            build,
            handoff,
        )
    }

    /// Builds and commits a pin acquisition while its exact authority stays locked.
    ///
    /// # Errors
    ///
    /// Returns an error when authority, typed construction, replay, or commit fails closed.
    pub fn commit_authorized_pin_acquisition<R>(
        &mut self,
        transaction_id: [u8; 16],
        requests: Vec<CacheResidencyAuthorityRequestV1>,
        build: impl for<'session, 'authority, 'journal> FnOnce(
            &CacheResidencyAuthorizedControllerV1<'session, 'authority, 'journal>,
        ) -> Result<
            Vec<CacheResidencyControllerRecordV1<'session>>,
            CacheResidencyProtectedJournalErrorV1,
        >,
        handoff: impl for<'current> FnOnce(ValidatedCacheResidencyPostcommitV1<'current>) -> R,
    ) -> Result<(CacheResidencyCommitOutcomeV1, Option<R>), CacheResidencyProtectedJournalErrorV1>
    {
        self.commit_authorized_transition(
            transaction_id,
            CacheResidencyTransactionKindV1::PinChange,
            &[CacheAuthorityPurposeV1::PinAcquire],
            requests,
            build,
            handoff,
        )
    }

    /// Builds and commits a pin release while exact drain evidence stays locked.
    ///
    /// # Errors
    ///
    /// Returns an error when authority, typed construction, replay, or commit fails closed.
    pub fn commit_authorized_pin_release<R>(
        &mut self,
        transaction_id: [u8; 16],
        requests: Vec<CacheResidencyAuthorityRequestV1>,
        build: impl for<'session, 'authority, 'journal> FnOnce(
            &CacheResidencyAuthorizedControllerV1<'session, 'authority, 'journal>,
        ) -> Result<
            Vec<CacheResidencyControllerRecordV1<'session>>,
            CacheResidencyProtectedJournalErrorV1,
        >,
        handoff: impl for<'current> FnOnce(ValidatedCacheResidencyPostcommitV1<'current>) -> R,
    ) -> Result<(CacheResidencyCommitOutcomeV1, Option<R>), CacheResidencyProtectedJournalErrorV1>
    {
        self.commit_authorized_transition(
            transaction_id,
            CacheResidencyTransactionKindV1::PinChange,
            &[CacheAuthorityPurposeV1::PinDrain],
            requests,
            build,
            handoff,
        )
    }

    /// Builds and commits a scrub result while exact scrub authority stays locked.
    ///
    /// # Errors
    ///
    /// Returns an error when authority, typed construction, replay, or commit fails closed.
    pub fn commit_authorized_scrub<R>(
        &mut self,
        transaction_id: [u8; 16],
        requests: Vec<CacheResidencyAuthorityRequestV1>,
        build: impl for<'session, 'authority, 'journal> FnOnce(
            &CacheResidencyAuthorizedControllerV1<'session, 'authority, 'journal>,
        ) -> Result<
            Vec<CacheResidencyControllerRecordV1<'session>>,
            CacheResidencyProtectedJournalErrorV1,
        >,
        handoff: impl for<'current> FnOnce(ValidatedCacheResidencyPostcommitV1<'current>) -> R,
    ) -> Result<(CacheResidencyCommitOutcomeV1, Option<R>), CacheResidencyProtectedJournalErrorV1>
    {
        self.commit_authorized_transition(
            transaction_id,
            CacheResidencyTransactionKindV1::Scrub,
            &[CacheAuthorityPurposeV1::Scrub],
            requests,
            build,
            handoff,
        )
    }

    /// Builds and commits eviction preparation while its exact authority stays locked.
    ///
    /// # Errors
    ///
    /// Returns an error when authority, typed construction, replay, or commit fails closed.
    pub fn commit_authorized_eviction_prepare<R>(
        &mut self,
        transaction_id: [u8; 16],
        requests: Vec<CacheResidencyAuthorityRequestV1>,
        build: impl for<'session, 'authority, 'journal> FnOnce(
            &CacheResidencyAuthorizedControllerV1<'session, 'authority, 'journal>,
        ) -> Result<
            Vec<CacheResidencyControllerRecordV1<'session>>,
            CacheResidencyProtectedJournalErrorV1,
        >,
        handoff: impl for<'current> FnOnce(ValidatedCacheResidencyPostcommitV1<'current>) -> R,
    ) -> Result<(CacheResidencyCommitOutcomeV1, Option<R>), CacheResidencyProtectedJournalErrorV1>
    {
        self.commit_authorized_transition(
            transaction_id,
            CacheResidencyTransactionKindV1::EvictionPrepare,
            &[CacheAuthorityPurposeV1::Eviction],
            requests,
            build,
            handoff,
        )
    }

    /// Commits one unlink observation while its exact authority stays locked.
    ///
    /// # Errors
    ///
    /// Returns an error when authority, typed construction, replay, or commit fails closed.
    pub fn commit_authorized_unlink_observation<R>(
        &mut self,
        transaction_id: [u8; 16],
        requests: Vec<CacheResidencyAuthorityRequestV1>,
        build: impl for<'session, 'authority, 'journal> FnOnce(
            &CacheResidencyAuthorizedControllerV1<'session, 'authority, 'journal>,
        ) -> Result<
            Vec<CacheResidencyControllerRecordV1<'session>>,
            CacheResidencyProtectedJournalErrorV1,
        >,
        handoff: impl for<'current> FnOnce(ValidatedCacheResidencyPostcommitV1<'current>) -> R,
    ) -> Result<(CacheResidencyCommitOutcomeV1, Option<R>), CacheResidencyProtectedJournalErrorV1>
    {
        self.commit_authorized_transition(
            transaction_id,
            CacheResidencyTransactionKindV1::EvictionFinalize,
            &[CacheAuthorityPurposeV1::UnlinkObservation],
            requests,
            build,
            handoff,
        )
    }

    /// Commits one ambiguity retry while observation and fencing authority stay locked.
    ///
    /// # Errors
    ///
    /// Returns an error when authority, typed construction, replay, or commit fails closed.
    pub fn commit_authorized_eviction_retry<R>(
        &mut self,
        transaction_id: [u8; 16],
        requests: Vec<CacheResidencyAuthorityRequestV1>,
        build: impl for<'session, 'authority, 'journal> FnOnce(
            &CacheResidencyAuthorizedControllerV1<'session, 'authority, 'journal>,
        ) -> Result<
            Vec<CacheResidencyControllerRecordV1<'session>>,
            CacheResidencyProtectedJournalErrorV1,
        >,
        handoff: impl for<'current> FnOnce(ValidatedCacheResidencyPostcommitV1<'current>) -> R,
    ) -> Result<(CacheResidencyCommitOutcomeV1, Option<R>), CacheResidencyProtectedJournalErrorV1>
    {
        self.commit_authorized_transition(
            transaction_id,
            CacheResidencyTransactionKindV1::EvictionFinalize,
            &[
                CacheAuthorityPurposeV1::UnlinkObservation,
                CacheAuthorityPurposeV1::Retry,
            ],
            requests,
            build,
            handoff,
        )
    }

    /// Commits exact physical reclamation while its observation authority stays locked.
    ///
    /// # Errors
    ///
    /// Returns an error when authority, typed construction, replay, or commit fails closed.
    pub fn commit_authorized_reclamation<R>(
        &mut self,
        transaction_id: [u8; 16],
        requests: Vec<CacheResidencyAuthorityRequestV1>,
        build: impl for<'session, 'authority, 'journal> FnOnce(
            &CacheResidencyAuthorizedControllerV1<'session, 'authority, 'journal>,
        ) -> Result<
            Vec<CacheResidencyControllerRecordV1<'session>>,
            CacheResidencyProtectedJournalErrorV1,
        >,
        handoff: impl for<'current> FnOnce(ValidatedCacheResidencyPostcommitV1<'current>) -> R,
    ) -> Result<(CacheResidencyCommitOutcomeV1, Option<R>), CacheResidencyProtectedJournalErrorV1>
    {
        self.commit_authorized_transition(
            transaction_id,
            CacheResidencyTransactionKindV1::EvictionFinalize,
            &[CacheAuthorityPurposeV1::Reclamation],
            requests,
            build,
            handoff,
        )
    }

    /// Runs one read-authority derivation while protected currentness remains locked.
    ///
    /// # Errors
    ///
    /// Returns an error when authority, full replay, or typed read derivation fails closed.
    pub fn with_authorized_read<R>(
        &mut self,
        requests: Vec<CacheResidencyAuthorityRequestV1>,
        read: impl for<'owner, 'authority, 'journal, 'capabilities> FnOnce(
            &'owner CacheAuthorityOwner<'authority, 'journal>,
            &'capabilities [VerifiedCacheCapabilityV1],
            u64,
        ) -> Result<
            R,
            CacheResidencyProtectedJournalErrorV1,
        >,
    ) -> Result<R, CacheResidencyProtectedJournalErrorV1> {
        self.validate_authority_requests(
            &[
                CacheAuthorityPurposeV1::Read,
                CacheAuthorityPurposeV1::Replay,
            ],
            &requests,
        )?;
        let selected = authority_request_keys(&requests);
        let authority = Arc::clone(&self.authority);
        authority.while_authority_current(
            &selected,
            |owner, capabilities, _now, validator, refresh| {
                let journal = self
                    .state_journal
                    .as_mut()
                    .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
                CacheResidencyProtectedJournalV1::claim(journal, validator)?.replay()?;
                let result = read(owner, capabilities, refresh()?)?;
                refresh()?;
                Ok(result)
            },
        )
    }

    fn commit_authorized_transition<R>(
        &mut self,
        transaction_id: [u8; 16],
        kind: CacheResidencyTransactionKindV1,
        allowed_purposes: &[CacheAuthorityPurposeV1],
        requests: Vec<CacheResidencyAuthorityRequestV1>,
        build: impl for<'session, 'authority, 'journal> FnOnce(
            &CacheResidencyAuthorizedControllerV1<'session, 'authority, 'journal>,
        ) -> Result<
            Vec<CacheResidencyControllerRecordV1<'session>>,
            CacheResidencyProtectedJournalErrorV1,
        >,
        handoff: impl for<'current> FnOnce(ValidatedCacheResidencyPostcommitV1<'current>) -> R,
    ) -> Result<(CacheResidencyCommitOutcomeV1, Option<R>), CacheResidencyProtectedJournalErrorV1>
    {
        self.validate_authority_requests(allowed_purposes, &requests)?;
        let selected = authority_request_keys(&requests);
        let authority = Arc::clone(&self.authority);
        authority.while_authority_current(
            &selected,
            |owner, capabilities, now, validator, refresh| {
                let controller = CacheResidencyAuthorizedControllerV1 {
                    owner,
                    capabilities,
                    transaction_kind: kind,
                    now,
                };
                let records = build(&controller)?;
                let journal = self
                    .state_journal
                    .as_mut()
                    .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
                let envelope_validator = validator.clone();
                let mut journal = CacheResidencyProtectedJournalV1::claim(journal, validator)?;
                let successors = cache_controller_successors(records, &envelope_validator)?;
                let prepared = journal.plan(transaction_id, kind, successors)?;
                refresh()?;
                let mut outcome = journal.commit(prepared)?;
                let handoff_result = match &mut outcome {
                    CacheResidencyCommitOutcomeV1::Applied(applied) => {
                        if refresh().is_err() {
                            return Ok((outcome, None));
                        }
                        let Some(capability) = applied.take_postcommit() else {
                            return Ok((outcome, None));
                        };
                        let validated = capability.consume(&journal)?;
                        Some(handoff(validated))
                    }
                    CacheResidencyCommitOutcomeV1::OutcomeUnknown { .. }
                    | CacheResidencyCommitOutcomeV1::ValidationUnknown { .. } => None,
                };
                Ok((outcome, handoff_result))
            },
        )
    }

    fn validate_authority_requests(
        &self,
        allowed_purposes: &[CacheAuthorityPurposeV1],
        requests: &[CacheResidencyAuthorityRequestV1],
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        let mut requested_purposes = std::collections::BTreeSet::new();
        let exact_purposes = requests.len() == allowed_purposes.len()
            && requests.iter().all(|request| {
                allowed_purposes.contains(&request.purpose())
                    && requested_purposes.insert(request.purpose() as u8)
            })
            && allowed_purposes
                .iter()
                .all(|purpose| requested_purposes.contains(&(*purpose as u8)));
        if !exact_purposes {
            return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
        }
        Ok(())
    }

    /// Commits one immutable checkpoint join without granting compaction authority.
    ///
    /// # Errors
    ///
    /// Returns an error when checkpoint shape, protected currentness, CAS, or
    /// exact readback fails closed.
    pub fn commit_checkpoint(
        &mut self,
        transaction_id: [u8; 16],
        partition: PhysicalPartitionId,
        checkpoint: &CacheTypedCheckpointV1,
    ) -> Result<CacheResidencyCommitOutcomeV1, CacheResidencyProtectedJournalErrorV1> {
        let authority = Arc::clone(&self.authority);
        authority.while_authority_current(&[], |_owner, _capabilities, _now, validator, refresh| {
            let journal = self
                .state_journal
                .as_mut()
                .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            let mut journal = CacheResidencyProtectedJournalV1::claim(journal, validator)?;
            let prepared = journal.plan_checkpoint(transaction_id, partition, checkpoint)?;
            refresh()?;
            journal.commit(prepared)
        })
    }

    /// Reopens protected state while retaining every ambiguous recovery result.
    ///
    /// The caller supplies the durable transaction identity for cold recovery
    /// if an internal classification handoff cannot preserve its opaque token.
    /// Reopen, replay, and final authority failures never turn a protected
    /// result or physical callback into an unqualified public success.
    pub fn recover<R>(
        &mut self,
        transaction_id: [u8; 16],
        pending: CacheResidencyOutcomeUnknownV1,
        handoff: impl for<'current> FnOnce(ValidatedCacheResidencyPostcommitV1<'current>) -> R,
    ) -> CacheResidencyProtectedOwnerRecoveryV1<R> {
        if let Err(cause) = self.reopen_state() {
            return CacheResidencyProtectedOwnerRecoveryV1::Pending {
                transaction_id,
                pending,
                cause,
            };
        }

        let mut pending = Some(pending);
        let mut classified = None;
        let authority = Arc::clone(&self.authority);
        let result = authority.while_authority_current(
            &[],
            |_owner, _capabilities, _now, validator, refresh| {
                let journal = self
                    .state_journal
                    .as_mut()
                    .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
                let journal = CacheResidencyProtectedJournalV1::claim(journal, validator)?;
                let exact = pending
                    .take()
                    .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
                let mut recovery = journal.recover(exact);
                let handoff_result = match &mut recovery {
                    CacheResidencyRecoveryV1::Applied(applied) => {
                        if let Err(cause) = refresh() {
                            classified = Some((recovery, None));
                            return Err(cause);
                        }
                        let Some(capability) = applied.take_postcommit() else {
                            classified = Some((recovery, None));
                            return Ok(());
                        };
                        let validated = match capability.consume(&journal) {
                            Ok(validated) => validated,
                            Err(cause) => {
                                classified = Some((recovery, None));
                                return Err(cause);
                            }
                        };
                        Some(handoff(validated))
                    }
                    CacheResidencyRecoveryV1::Retry(_)
                    | CacheResidencyRecoveryV1::Diverged(_)
                    | CacheResidencyRecoveryV1::Indeterminate { .. } => None,
                };
                classified = Some((recovery, handoff_result));
                Ok(())
            },
        );

        match (classified, pending, result) {
            (Some((recovery, handoff)), _, Ok(())) => {
                CacheResidencyProtectedOwnerRecoveryV1::Classified {
                    transaction_id,
                    recovery,
                    handoff,
                    authority_error: None,
                }
            }
            (Some((recovery, handoff)), _, Err(cause)) => {
                CacheResidencyProtectedOwnerRecoveryV1::Classified {
                    transaction_id,
                    recovery,
                    handoff,
                    authority_error: Some(cause),
                }
            }
            (None, Some(pending), Err(cause)) => CacheResidencyProtectedOwnerRecoveryV1::Pending {
                transaction_id,
                pending,
                cause,
            },
            (None, Some(pending), Ok(())) => CacheResidencyProtectedOwnerRecoveryV1::Pending {
                transaction_id,
                pending,
                cause: ProtectedDomainJournalErrorV1::StaleAuthority,
            },
            (None, _, result) => CacheResidencyProtectedOwnerRecoveryV1::ColdLookupRequired {
                transaction_id,
                cause: result
                    .err()
                    .unwrap_or(ProtectedDomainJournalErrorV1::StaleAuthority),
            },
        }
    }

    /// Resolves one cold transaction without granting blind effect replay.
    ///
    /// # Errors
    ///
    /// Returns an error when grouping, typed replay, time, or authority
    /// validation fails.
    pub fn resolve_current_transaction<R>(
        &mut self,
        transaction_id: [u8; 16],
        observation: Option<([u8; 16], ObjectDigest)>,
        handoff: impl for<'current> FnOnce(ValidatedCacheResidencyPostcommitV1<'current>) -> R,
    ) -> Result<CacheResidencyProtectedColdOutcomeV1<R>, CacheResidencyProtectedJournalErrorV1>
    {
        let authority = Arc::clone(&self.authority);
        authority.while_authority_current(&[], |_owner, _capabilities, _now, validator, refresh| {
            let journal = self
                .state_journal
                .as_mut()
                .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            let mut journal = CacheResidencyProtectedJournalV1::claim(journal, validator)?;
            match journal.recover_current_transaction(transaction_id)? {
                CacheResidencyColdRecoveryV1::StateOnly => {
                    refresh()?;
                    Ok(CacheResidencyProtectedColdOutcomeV1::StateOnly)
                }
                CacheResidencyColdRecoveryV1::ObservePending(cold) => {
                    let Some((settlement_transaction_id, evidence)) = observation else {
                        refresh()?;
                        return Ok(CacheResidencyProtectedColdOutcomeV1::ObservationRequired);
                    };
                    let prepared =
                        journal.plan_cold_observation(settlement_transaction_id, cold, evidence)?;
                    refresh()?;
                    let outcome = journal.commit(prepared)?;
                    Ok(CacheResidencyProtectedColdOutcomeV1::ObservationCommitted(
                        outcome,
                    ))
                }
                CacheResidencyColdRecoveryV1::Terminal(cold) => {
                    refresh()?;
                    let validated = cold.consume(&journal)?;
                    Ok(CacheResidencyProtectedColdOutcomeV1::Terminal(handoff(
                        validated,
                    )))
                }
            }
        })
    }

    /// Reconciles a cold pin transaction only after exact physical observation.
    ///
    /// This is narrower than generic cold effect recovery: the owner manifest
    /// proves whether this exact pin action is already settled before an
    /// admission can be applied. The caller must derive `transaction_id` from
    /// its durable operation and pin identity. The expected action and exact
    /// pin must match the recovered protected event before any physical effect.
    /// An arbitrary historical ID cannot grant an effect if that event is no
    /// longer current.
    ///
    /// # Errors
    ///
    /// Returns an error when protected replay, currentness, or exact
    /// transaction classification fails closed. Physical failures are retained
    /// in the result so the caller can retry the same transaction identity.
    #[cfg(target_os = "linux")]
    pub fn reconcile_current_pin_change(
        &mut self,
        transaction_id: [u8; 16],
        expected_action: super::CacheOwnerPinActionV1,
        expected_pin: &CachePinV1,
        physical: &mut super::DormantCacheOwnerV1,
    ) -> Result<CacheResidencyProtectedPinRecoveryV1, CacheResidencyProtectedJournalErrorV1> {
        let authority = Arc::clone(&self.authority);
        authority.while_authority_current(&[], |_owner, _capabilities, _now, validator, refresh| {
            let journal = self
                .state_journal
                .as_mut()
                .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            let journal = CacheResidencyProtectedJournalV1::claim(journal, validator)?;
            let cold = match journal.recover_current_transaction(transaction_id)? {
                CacheResidencyColdRecoveryV1::StateOnly => {
                    refresh()?;
                    return Ok(CacheResidencyProtectedPinRecoveryV1::StateOnly);
                }
                CacheResidencyColdRecoveryV1::ObservePending(cold)
                | CacheResidencyColdRecoveryV1::Terminal(cold) => cold,
            };
            refresh()?;
            let validated = cold.consume(&journal)?;
            Ok(
                match validated.reconcile_cache_owner_pin_change(
                    physical,
                    expected_action,
                    expected_pin,
                ) {
                    Ok(settlement) => CacheResidencyProtectedPinRecoveryV1::Settled(settlement),
                    Err(error) => CacheResidencyProtectedPinRecoveryV1::PhysicalError(error),
                },
            )
        })
    }

    /// Recovers a public acquisition using its original protected operation.
    ///
    /// The original event supplies the physical pin and partition, so a retry
    /// cannot redirect a cold handoff by selecting a different current
    /// partition. The event must still retain the same logical consumer.
    ///
    /// # Errors
    ///
    /// Returns an error when protected replay or exact consumer validation
    /// fails closed. Physical failures remain in the result for exact retry.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_current_public_logical_pin_acquisition(
        &mut self,
        transaction_id: [u8; 16],
        operation: OperationId,
        object: &ObjectDescriptor,
        project: ProjectId,
        view: ViewId,
        attachment: Option<AttachmentId>,
        physical: &mut super::DormantCacheOwnerV1,
    ) -> Result<CacheResidencyProtectedPinRecoveryV1, CacheResidencyProtectedJournalErrorV1> {
        let authority = Arc::clone(&self.authority);
        authority.while_authority_current(&[], |_owner, _capabilities, _now, validator, refresh| {
            let journal = self
                .state_journal
                .as_mut()
                .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            let journal = CacheResidencyProtectedJournalV1::claim(journal, validator)?;
            let cold = match journal.recover_current_transaction(transaction_id)? {
                CacheResidencyColdRecoveryV1::StateOnly => {
                    refresh()?;
                    return Ok(CacheResidencyProtectedPinRecoveryV1::StateOnly);
                }
                CacheResidencyColdRecoveryV1::ObservePending(cold)
                | CacheResidencyColdRecoveryV1::Terminal(cold) => cold,
            };
            refresh()?;
            let validated = cold.consume(&journal)?;
            Ok(
                match validated.reconcile_public_logical_pin_acquisition(
                    physical, operation, object, project, view, attachment,
                ) {
                    Ok(settlement) => CacheResidencyProtectedPinRecoveryV1::Settled(settlement),
                    Err(error) => CacheResidencyProtectedPinRecoveryV1::PhysicalError(error),
                },
            )
        })
    }

    fn reopen_state(&mut self) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        drop(self.state_journal.take());
        let (journal, _) = open_cache_journal(
            Path::new(PROTECTED_CACHE_ROOT),
            CACHE_STATE_JOURNAL,
            cache_state_journal_limits(),
            self.owner_uid,
        )?;
        self.state_journal = Some(journal);
        Ok(())
    }
}

/// Retires one closed Cache hold using immutable historical replay only.
///
/// This one-shot path retains clock, authority, and state writer locks before
/// taking the hold lock and checking root. It does not construct a live Cache
/// owner, renew expired Replay authority, or expose a mutation capability.
/// `owner_uid` must come from the offline deployment identity, not a request.
///
/// # Errors
///
/// Rejects malformed or mismatched Cache history, missing held custody, failed
/// root readback, or failed durable release.
pub(crate) fn release_fixed_closed_policy_cache_hold_after_root_readback_v1(
    owner_uid: u32,
    expected: CachePolicyHoldV1,
    verify_root: impl FnOnce() -> Result<(), CacheResidencyProtectedJournalErrorV1>,
) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
    if owner_uid == 0 {
        return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
    }
    reject_legacy_cache_journals()?;
    release_closed_policy_cache_hold_at(
        Path::new(PROTECTED_CACHE_ROOT),
        owner_uid,
        expected,
        verify_root,
    )
}

fn release_closed_policy_cache_hold_at(
    root: &Path,
    owner_uid: u32,
    expected: CachePolicyHoldV1,
    verify_root: impl FnOnce() -> Result<(), CacheResidencyProtectedJournalErrorV1>,
) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
    // The clock lock is retained for the ordinary owner's lock order, but
    // wall-clock expiry is deliberately not promoted into release authority.
    let (mut clock, _) = open_cache_journal(
        root,
        CACHE_CLOCK_JOURNAL,
        cache_clock_journal_limits(),
        owner_uid,
    )?;
    {
        let clock_authority = clock.claim_protected_authority(RecordNamespace::DesiredState)?;
        let mut records = clock_authority.records()?;
        let Some((key, value)) = records.next() else {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        };
        let floor = decode_cache_clock_floor(value)?;
        if key != CACHE_CLOCK_KEY
            || floor.owner_scope != cache_owner_scope()
            || records.next().is_some()
        {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
    }
    let (mut authority, _) = open_cache_journal(
        root,
        CACHE_AUTHORITY_JOURNAL,
        cache_authority_journal_limits(),
        owner_uid,
    )?;
    let evidence = recover_cache_replay_evidence(
        &mut authority,
        cache_owner_scope(),
        CacheRecoveryLimitsV1::default(),
    )?;
    let (mut state, _) = open_cache_journal(
        root,
        CACHE_STATE_JOURNAL,
        cache_state_journal_limits(),
        owner_uid,
    )?;
    let inventories = replay_closed_policy_historical_inventories(
        &mut authority,
        &mut state,
        cache_owner_scope(),
        MAXIMUM_AUTHORITY_RECORD_BYTES,
        evidence,
        CacheRecoveryLimitsV1::default(),
    )?;
    let current = select_project_physical_cache_head(expected.project(), inventories)?;
    if current.partition().digest() != expected.partition()
        || current.head() != expected.cache_head()
    {
        return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
    }

    Journal::release_cache_policy_hold_if_at(root, owner_uid, expected, verify_root)
}

fn cache_controller_successors(
    records: Vec<CacheResidencyControllerRecordV1<'_>>,
    validator: &CacheResidencyReplayValidatorV1,
) -> Result<Vec<CacheResidencyProtectedJournalEnvelopeV1>, CacheResidencyProtectedJournalErrorV1> {
    records
        .into_iter()
        .map(|record| {
            let (kind, payload, authority_record) = record.into_parts();
            if payload.record.authority != authority_record
                && payload.record.evidence != authority_record
            {
                return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
            }
            let partition = payload.plan.partition;
            let project = (kind == CacheResidencyProtectedRecordKindV1::ProjectAccounting)
                .then_some(payload.plan.project);
            let key = cache_residency_protected_key_v1(
                kind,
                partition,
                project,
                payload.record.subject,
                Some((payload.record.sequence, payload.record.digest)),
            )?;
            cache_residency_reducer_envelope_v1(key, 1, None, partition, &payload, validator)
        })
        .collect()
}

fn authority_request_keys(
    requests: &[CacheResidencyAuthorityRequestV1],
) -> Vec<(CacheAuthorityPurposeV1, Vec<u8>)> {
    requests
        .iter()
        .map(|request| (request.purpose(), request.record_key().to_vec()))
        .collect()
}

struct ProtectedCacheClockV1 {
    state: Mutex<ProtectedCacheClockStateV1>,
    owner_scope: ObjectDigest,
    owner_uid: u32,
}

struct ProtectedCacheClockStateV1 {
    journal: Option<Journal>,
    floor: CacheClockFloorV1,
}

#[derive(Clone, Copy)]
struct CacheClockFloorV1 {
    owner_scope: ObjectDigest,
    revision: u64,
    observed_unix_seconds: u64,
    predecessor_unix_seconds: u64,
}

impl ProtectedCacheClockV1 {
    fn open(
        root: &Path,
        owner_scope: ObjectDigest,
        owner_uid: u32,
    ) -> Result<(Self, RecoveryReport), CacheResidencyProtectedJournalErrorV1> {
        let (mut journal, report) = open_cache_journal(
            root,
            CACHE_CLOCK_JOURNAL,
            cache_clock_journal_limits(),
            owner_uid,
        )?;
        let retained = {
            let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
            authority
                .get(CACHE_CLOCK_KEY)?
                .map(decode_cache_clock_floor)
                .transpose()?
        };
        let sampled = sample_wall_clock()?;
        let floor = match retained {
            Some(floor)
                if floor.owner_scope == owner_scope && floor.observed_unix_seconds <= sampled =>
            {
                floor
            }
            Some(_) => return Err(ProtectedDomainJournalErrorV1::StaleAuthority),
            None => {
                let genesis = CacheClockFloorV1 {
                    owner_scope,
                    revision: 1,
                    observed_unix_seconds: sampled,
                    predecessor_unix_seconds: 0,
                };
                let (reopened, applied) = persist_cache_clock(journal, None, genesis, owner_uid)?;
                if !applied {
                    return Err(ProtectedDomainJournalErrorV1::CompareAndSwapFailed);
                }
                journal = reopened;
                genesis
            }
        };
        Ok((
            Self {
                state: Mutex::new(ProtectedCacheClockStateV1 {
                    journal: Some(journal),
                    floor,
                }),
                owner_scope,
                owner_uid,
            },
            report,
        ))
    }
}

impl CacheResidencyCurrentTimeAuthorityV1 for ProtectedCacheClockV1 {
    fn current_unix_seconds(&self) -> Result<u64, CacheResidencyProtectedJournalErrorV1> {
        let sampled = sample_wall_clock()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if state.floor.owner_scope != self.owner_scope
            || sampled < state.floor.observed_unix_seconds
        {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        if sampled == state.floor.observed_unix_seconds {
            return Ok(sampled);
        }
        let successor = CacheClockFloorV1 {
            owner_scope: self.owner_scope,
            revision: state
                .floor
                .revision
                .checked_add(1)
                .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?,
            observed_unix_seconds: sampled,
            predecessor_unix_seconds: state.floor.observed_unix_seconds,
        };
        let journal = state
            .journal
            .take()
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let (reopened, applied) =
            persist_cache_clock(journal, Some(state.floor), successor, self.owner_uid)?;
        state.journal = Some(reopened);
        if !applied {
            return Err(ProtectedDomainJournalErrorV1::CompareAndSwapFailed);
        }
        state.floor = successor;
        Ok(sampled)
    }
}

fn persist_cache_clock(
    mut journal: Journal,
    predecessor: Option<CacheClockFloorV1>,
    successor: CacheClockFloorV1,
    owner_uid: u32,
) -> Result<(Journal, bool), CacheResidencyProtectedJournalErrorV1> {
    let encoded = encode_cache_clock_floor(successor);
    let transaction_id = cache_clock_transaction_id(&encoded)?;
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            CACHE_CLOCK_KEY.to_vec(),
            encoded.clone(),
        )],
    )?;
    {
        let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
        let current = authority.get(CACHE_CLOCK_KEY)?.map(<[u8]>::to_vec);
        let expected = predecessor.map(encode_cache_clock_floor);
        if current.as_deref() != expected.as_deref() {
            return Err(ProtectedDomainJournalErrorV1::CompareAndSwapFailed);
        }
        let preflight = authority.preflight_transactions(std::slice::from_ref(&transaction))?;
        authority.validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;
        let _attempt = authority.commit(&transaction);
    }
    drop(journal);

    let (mut reopened, _) = open_cache_journal(
        Path::new(PROTECTED_CACHE_ROOT),
        CACHE_CLOCK_JOURNAL,
        cache_clock_journal_limits(),
        owner_uid,
    )?;
    let readback = {
        let authority = reopened.claim_protected_authority(RecordNamespace::DesiredState)?;
        authority.get(CACHE_CLOCK_KEY)?.map(<[u8]>::to_vec)
    };
    if readback.as_deref() == Some(encoded.as_slice()) {
        return Ok((reopened, true));
    }
    let expected = predecessor.map(encode_cache_clock_floor);
    if readback.as_deref() == expected.as_deref() {
        return Ok((reopened, false));
    }
    Err(ProtectedDomainJournalErrorV1::DivergentRecovery)
}

fn recover_cache_replay_evidence(
    journal: &mut Journal,
    owner_scope: ObjectDigest,
    limits: CacheRecoveryLimitsV1,
) -> Result<Vec<CacheResidencyReplayPartitionEvidenceV1>, CacheResidencyProtectedJournalErrorV1> {
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let owner = CacheAuthorityOwner::new(&authority, owner_scope, MAXIMUM_AUTHORITY_RECORD_BYTES)
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let mut evidence = Vec::new();
    for (key, value) in authority.records()? {
        if !key.starts_with(CACHE_MANIFEST_KEY_PREFIX) {
            continue;
        }
        if evidence.len() >= MAXIMUM_CACHE_MANIFESTS {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let item = decode_cache_replay_manifest(value, limits)?;
        if key.get(CACHE_MANIFEST_KEY_PREFIX.len()..) != Some(item.partition.digest().as_bytes()) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        owner
            .verify_current_record(item.purpose, item.scope, &item.record_key)
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        evidence.push(item);
    }
    if evidence.is_empty() {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    Ok(evidence)
}

pub(super) fn decode_cache_replay_manifest(
    bytes: &[u8],
    limits: CacheRecoveryLimitsV1,
) -> Result<CacheResidencyReplayPartitionEvidenceV1, CacheResidencyProtectedJournalErrorV1> {
    if bytes.len() < CACHE_MANIFEST_FIXED_BYTES
        || &bytes[..8] != CACHE_MANIFEST_MAGIC
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10..16] != [0; 6]
        || bytes[258..265] != [0; 7]
    {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    let partition = decode_partition_descriptor(&bytes[16..257])
        .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let purpose = decode_cache_authority_purpose(bytes[257])
        .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let operation_bytes: [u8; 16] = bytes[297..313]
        .try_into()
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let operation = (operation_bytes != [0; 16]).then(|| OperationId::from_bytes(operation_bytes));
    let scope = CacheAuthorityScopeV1::new(
        partition,
        ObjectDigest::from_bytes(read_array(bytes, 265)?),
        operation,
        ObjectDigest::from_bytes(read_array(bytes, 313)?),
        ObjectDigest::from_bytes(read_array(bytes, 345)?),
        read_u64(bytes, 377)?,
        read_u64(bytes, 385)?,
    )
    .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let floor = decode_floor(&bytes[393..545])
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let record_key_bytes = usize::from(read_u16(bytes, 545)?);
    let checkpoint_bytes = usize::try_from(read_u32(bytes, 547)?)
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let prior_bytes = usize::try_from(read_u32(bytes, 551)?)
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    if record_key_bytes == 0
        || record_key_bytes > 1024
        || checkpoint_bytes == 0
        || checkpoint_bytes > limits.maximum_payload_bytes
        || prior_bytes > limits.maximum_payload_bytes
        || CACHE_MANIFEST_FIXED_BYTES
            .checked_add(record_key_bytes)
            .and_then(|length| length.checked_add(checkpoint_bytes))
            .and_then(|length| length.checked_add(prior_bytes))
            != Some(bytes.len())
    {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    let record_key_end = CACHE_MANIFEST_FIXED_BYTES + record_key_bytes;
    let checkpoint_end = record_key_end + checkpoint_bytes;
    let record_key = bytes[CACHE_MANIFEST_FIXED_BYTES..record_key_end].to_vec();
    let typed_checkpoint = bytes[record_key_end..checkpoint_end].to_vec();
    let prior_typed_checkpoint = (prior_bytes != 0).then(|| bytes[checkpoint_end..].to_vec());
    decode_typed_checkpoint(partition, &typed_checkpoint, limits)
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    if let Some(prior) = prior_typed_checkpoint.as_deref() {
        decode_typed_checkpoint(partition, prior, limits)
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    }
    let evidence = CacheResidencyReplayPartitionEvidenceV1 {
        partition,
        purpose,
        scope,
        record_key,
        typed_checkpoint,
        prior_typed_checkpoint,
        floor,
    };
    if encode_cache_replay_manifest(&evidence, limits)?.as_slice() != bytes {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    Ok(evidence)
}

pub(super) fn encode_cache_replay_manifest(
    evidence: &CacheResidencyReplayPartitionEvidenceV1,
    limits: CacheRecoveryLimitsV1,
) -> Result<Vec<u8>, CacheResidencyProtectedJournalErrorV1> {
    let record_key_bytes = u16::try_from(evidence.record_key.len())
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let checkpoint_bytes = u32::try_from(evidence.typed_checkpoint.len())
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let prior = evidence
        .prior_typed_checkpoint
        .as_deref()
        .unwrap_or_default();
    let prior_bytes = u32::try_from(prior.len())
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let total_bytes = CACHE_MANIFEST_FIXED_BYTES
        .checked_add(evidence.record_key.len())
        .and_then(|length| length.checked_add(evidence.typed_checkpoint.len()))
        .and_then(|length| length.checked_add(prior.len()))
        .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
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
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    decode_typed_checkpoint(evidence.partition, &evidence.typed_checkpoint, limits)
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    if !prior.is_empty() {
        decode_typed_checkpoint(evidence.partition, prior, limits)
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
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
        &encode_floor(&evidence.floor)
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?,
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

fn decode_cache_authority_purpose(code: u8) -> Option<CacheAuthorityPurposeV1> {
    use CacheAuthorityPurposeV1 as Purpose;
    Some(match code {
        1 => Purpose::Source,
        2 => Purpose::Read,
        3 => Purpose::Admission,
        4 => Purpose::Eviction,
        5 => Purpose::PinDrain,
        6 => Purpose::UnlinkObservation,
        7 => Purpose::Reclamation,
        8 => Purpose::Scrub,
        9 => Purpose::Retry,
        10 => Purpose::Replay,
        11 => Purpose::PinAcquire,
        12 => Purpose::AdmissionCleanup,
        13 => Purpose::PendingCancellation,
        _ => return None,
    })
}

fn cache_owner_scope() -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.cache-residency.fixed-owner.v1\0")
            .chain_update(PROTECTED_CACHE_ROOT.as_bytes())
            .finalize()
            .into(),
    )
}

fn sample_wall_clock() -> Result<u64, CacheResidencyProtectedJournalErrorV1> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?
        .as_secs();
    if now == 0 {
        return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
    }
    Ok(now)
}

fn encode_cache_clock_floor(floor: CacheClockFloorV1) -> Vec<u8> {
    let mut bytes = vec![0_u8; CACHE_CLOCK_BYTES];
    bytes[..8].copy_from_slice(CACHE_CLOCK_MAGIC);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..48].copy_from_slice(floor.owner_scope.as_bytes());
    bytes[48..56].copy_from_slice(&floor.revision.to_be_bytes());
    bytes[56..64].copy_from_slice(&floor.observed_unix_seconds.to_be_bytes());
    bytes[64..72].copy_from_slice(&floor.predecessor_unix_seconds.to_be_bytes());
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.cache-residency.clock-floor.v1\0")
        .chain_update(&bytes[..72])
        .finalize();
    bytes[72..104].copy_from_slice(&digest);
    bytes
}

fn decode_cache_clock_floor(
    bytes: &[u8],
) -> Result<CacheClockFloorV1, CacheResidencyProtectedJournalErrorV1> {
    if bytes.len() != CACHE_CLOCK_BYTES
        || &bytes[..8] != CACHE_CLOCK_MAGIC
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10..16] != [0; 6]
        || bytes[72..104]
            != Sha256::new()
                .chain_update(b"aos.sandbox.cache-residency.clock-floor.v1\0")
                .chain_update(&bytes[..72])
                .finalize()[..]
    {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    let floor = CacheClockFloorV1 {
        owner_scope: ObjectDigest::from_bytes(read_array(bytes, 16)?),
        revision: read_u64(bytes, 48)?,
        observed_unix_seconds: read_u64(bytes, 56)?,
        predecessor_unix_seconds: read_u64(bytes, 64)?,
    };
    if floor.owner_scope.as_bytes() == &[0; 32]
        || floor.revision == 0
        || floor.observed_unix_seconds == 0
        || (floor.revision == 1 && floor.predecessor_unix_seconds != 0)
        || (floor.revision > 1
            && (floor.predecessor_unix_seconds == 0
                || floor.predecessor_unix_seconds > floor.observed_unix_seconds))
    {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    Ok(floor)
}

fn cache_clock_transaction_id(
    encoded: &[u8],
) -> Result<[u8; 16], CacheResidencyProtectedJournalErrorV1> {
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.cache-residency.clock-transaction.v1\0")
        .chain_update(encoded)
        .finalize();
    let transaction_id: [u8; 16] = digest[..16]
        .try_into()
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    if transaction_id == [0; 16] {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    Ok(transaction_id)
}

fn cache_state_journal_limits() -> JournalLimits {
    JournalLimits::default()
}

fn cache_authority_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_record_bytes: 16 * 1024 * 1024,
        maximum_materialized_records: 16_384,
        ..JournalLimits::default()
    }
}

fn cache_clock_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 16 * 1024 * 1024,
        maximum_record_bytes: 4 * 1024,
        maximum_key_bytes: 128,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: 8 * 1024,
        maximum_transactions: 262_144,
        maximum_materialized_bytes: 8 * 1024,
        maximum_materialized_records: 1,
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, CacheResidencyProtectedJournalErrorV1> {
    Ok(u16::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, CacheResidencyProtectedJournalErrorV1> {
    Ok(u32::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, CacheResidencyProtectedJournalErrorV1> {
    Ok(u64::from_be_bytes(read_array(bytes, offset)?))
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], CacheResidencyProtectedJournalErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    use aos_sandbox_core::CacheDomainId;
    use aos_sandbox_core::model::CacheDomain;

    use super::*;
    use crate::cache_residency::{
        BackingIsolationV1, CacheIsolationPolicyV1, CacheNodeIdV1, NodeCacheQuotaV1,
        ProjectCacheQuotaV1, ProtectedBackingIdentityV1, ResidencyEnforcementV1,
        encode_cache_replay_genesis_manifest_v1,
    };

    struct ExpiredReplayTime;

    impl CacheResidencyCurrentTimeAuthorityV1 for ExpiredReplayTime {
        fn current_unix_seconds(&self) -> Result<u64, CacheResidencyProtectedJournalErrorV1> {
            Ok(2)
        }
    }

    fn expired_cache_hold_fixture() -> (tempfile::TempDir, u32, CachePolicyHoldV1) {
        let directory = tempfile::tempdir().expect("protected Cache fixture");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private Cache directory");
        let uid = fs::metadata(directory.path())
            .expect("Cache metadata")
            .uid();
        let project = ProjectId::from_bytes([1; 16]);
        let node = CacheNodeIdV1::from_bytes([2; 16]).expect("node");
        let backing = ProtectedBackingIdentityV1::new(
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            ObjectDigest::from_bytes([5; 32]),
            ObjectDigest::from_bytes([6; 32]),
        )
        .expect("backing");
        let domain = CacheDomain::new(
            CacheDomainKind::Project,
            CacheDomainId::from_bytes(*project.as_bytes()),
        );
        let isolation = CacheIsolationPolicyV1 {
            backing: BackingIsolationV1::SeparateFilesystemOrDataset,
            residency: ResidencyEnforcementV1::HardIsolatedResidency,
            reflink_or_clone: false,
            block_deduplication: false,
            shared_page_cache: false,
            fetch_coalescing: false,
            strict: true,
            revision: 1,
        };
        let partition =
            PhysicalPartitionId::from_policy(node, backing, domain, isolation).expect("partition");
        let node_quota = NodeCacheQuotaV1 {
            partition,
            maximum_physical_bytes: 1024 * 1024,
            maximum_resident_objects: 16,
            maximum_logical_pins: 16,
            maximum_source_retentions: 16,
            maximum_kernel_references: 16,
            maximum_backing_registrations: 16,
            recovery_reserve_bytes: 4096,
            high_water_bytes: 768 * 1024,
            low_water_bytes: 512 * 1024,
        };
        let project_quota = ProjectCacheQuotaV1 {
            project,
            partition,
            maximum_charged_bytes: 1024 * 1024,
            maximum_logical_pins: 16,
            maximum_source_retentions: 16,
            maximum_kernel_references: 16,
            maximum_backing_registrations: 16,
        };
        let manifest =
            encode_cache_replay_genesis_manifest_v1(partition, node_quota, vec![project_quota], 1)
                .expect("expired canonical manifest");
        let evidence = decode_cache_replay_manifest(&manifest, CacheRecoveryLimitsV1::default())
            .expect("decoded Replay evidence");

        let (mut clock, _) = open_cache_journal(
            directory.path(),
            CACHE_CLOCK_JOURNAL,
            cache_clock_journal_limits(),
            uid,
        )
        .expect("clock journal");
        clock
            .commit(
                &JournalTransaction::new(
                    [7; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::DesiredState,
                        CACHE_CLOCK_KEY.to_vec(),
                        encode_cache_clock_floor(CacheClockFloorV1 {
                            owner_scope: cache_owner_scope(),
                            revision: 1,
                            observed_unix_seconds: 1,
                            predecessor_unix_seconds: 0,
                        }),
                    )],
                )
                .expect("clock transaction"),
            )
            .expect("clock floor");
        drop(clock);

        let (mut authority, _) = open_cache_journal(
            directory.path(),
            CACHE_AUTHORITY_JOURNAL,
            cache_authority_journal_limits(),
            uid,
        )
        .expect("authority journal");
        let canonical = {
            let claimed = authority
                .claim_protected_authority(RecordNamespace::DesiredState)
                .expect("protected authority");
            CacheAuthorityOwner::new(
                &claimed,
                cache_owner_scope(),
                MAXIMUM_AUTHORITY_RECORD_BYTES,
            )
            .expect("Replay authority")
            .canonical_record(CacheAuthorityPurposeV1::Replay, evidence.scope)
        };
        let mut manifest_key = CACHE_MANIFEST_KEY_PREFIX.to_vec();
        manifest_key.extend_from_slice(partition.digest().as_bytes());
        authority
            .commit(
                &JournalTransaction::new(
                    [8; 16],
                    vec![
                        JournalRecord::put(
                            RecordNamespace::DesiredState,
                            evidence.record_key.clone(),
                            canonical.to_vec(),
                        ),
                        JournalRecord::put(RecordNamespace::DesiredState, manifest_key, manifest),
                    ],
                )
                .expect("authority transaction"),
            )
            .expect("Replay authority and manifest");
        let recovered = recover_cache_replay_evidence(
            &mut authority,
            cache_owner_scope(),
            CacheRecoveryLimitsV1::default(),
        )
        .expect("recovered manifest");
        let (mut state, _) = open_cache_journal(
            directory.path(),
            CACHE_STATE_JOURNAL,
            cache_state_journal_limits(),
            uid,
        )
        .expect("state journal");
        let inventories = replay_closed_policy_historical_inventories(
            &mut authority,
            &mut state,
            cache_owner_scope(),
            MAXIMUM_AUTHORITY_RECORD_BYTES,
            recovered,
            CacheRecoveryLimitsV1::default(),
        )
        .expect("historical typed replay");
        let current =
            select_project_physical_cache_head(project, inventories).expect("project Cache head");
        drop(state);
        drop(authority);

        let hold = CachePolicyHoldV1::new(
            project,
            current.partition().digest(),
            current.head(),
            ObjectDigest::from_bytes([9; 32]),
            5,
        )
        .expect("closed Cache hold");
        Journal::acquire_cache_policy_hold_at(directory.path(), uid, hold)
            .expect("durable Cache hold");
        (directory, uid, hold)
    }

    #[test]
    fn legacy_journal_names_fail_closed_before_new_store_creation() {
        let directory = tempfile::tempdir().expect("legacy root");
        assert!(reject_legacy_cache_journals_at(directory.path()).is_ok());

        for name in [
            CACHE_STATE_JOURNAL,
            CACHE_AUTHORITY_JOURNAL,
            CACHE_CLOCK_JOURNAL,
        ] {
            for suffix in ["", ".lock", ".compact.tmp"] {
                let legacy = directory.path().join(format!("{name}{suffix}"));
                symlink("missing", &legacy).expect("legacy symlink");
                assert!(matches!(
                    reject_legacy_cache_journals_at(directory.path()),
                    Err(crate::journal::JournalError::ProtectedBoundary)
                ));
                std::fs::remove_file(legacy).expect("remove fixture");
            }
        }
    }

    #[test]
    fn hold_only_legacy_names_fail_closed_before_new_store_creation() {
        let directory = tempfile::tempdir().expect("legacy hold root");
        for suffix in ["", ".lock", ".compact.tmp"] {
            let legacy = directory
                .path()
                .join(format!("{CACHE_POLICY_HOLD_JOURNAL}{suffix}"));
            symlink("missing", &legacy).expect("hold-only legacy symlink");
            assert!(matches!(
                reject_legacy_cache_journals_at(directory.path()),
                Err(crate::journal::JournalError::ProtectedBoundary)
            ));
            std::fs::remove_file(&legacy).expect("remove hold-only fixture");
            assert!(reject_legacy_cache_journals_at(directory.path()).is_ok());
        }
    }

    #[test]
    fn project_physical_cache_selection_requires_exactly_one_owner_head() {
        let project = ProjectId::from_bytes([1; 16]);
        let node = CacheNodeIdV1::from_bytes([2; 16]).expect("node");
        let backing = ProtectedBackingIdentityV1::new(
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            ObjectDigest::from_bytes([5; 32]),
            ObjectDigest::from_bytes([6; 32]),
        )
        .expect("backing");
        let domain = CacheDomain::new(
            CacheDomainKind::Project,
            CacheDomainId::from_bytes(*project.as_bytes()),
        );
        let partition =
            PhysicalPartitionId::derive(node, backing, domain, ObjectDigest::from_bytes([7; 32]))
                .expect("partition");
        let current = CurrentProjectPhysicalCacheHeadV1 {
            project,
            partition,
            head: project_physical_cache_head_digest(
                project,
                partition,
                ObjectDigest::from_bytes([8; 32]),
            ),
        };

        assert_ne!(
            current.head(),
            project_physical_cache_head_digest(
                project,
                partition,
                ObjectDigest::from_bytes([9; 32]),
            )
        );
        assert!(unique_project_physical_cache_head(Vec::new()).is_err());
        assert_eq!(
            unique_project_physical_cache_head([current]).expect("unique"),
            current
        );
        assert!(unique_project_physical_cache_head([current, current]).is_err());
    }

    #[test]
    fn expired_replay_cannot_block_exact_closed_cache_hold_retirement() {
        let (directory, uid, hold) = expired_cache_hold_fixture();
        let (mut authority, _) = open_cache_journal(
            directory.path(),
            CACHE_AUTHORITY_JOURNAL,
            cache_authority_journal_limits(),
            uid,
        )
        .expect("expired authority journal");
        let evidence = recover_cache_replay_evidence(
            &mut authority,
            cache_owner_scope(),
            CacheRecoveryLimitsV1::default(),
        )
        .expect("expired manifest remains authentic");
        assert!(
            CacheResidencyReplayValidatorV1::from_protected_authority(
                authority,
                cache_owner_scope(),
                MAXIMUM_AUTHORITY_RECORD_BYTES,
                evidence,
                CacheRecoveryLimitsV1::default(),
                Arc::new(ExpiredReplayTime),
            )
            .is_err()
        );

        let wrong = CachePolicyHoldV1::new(
            hold.project(),
            hold.partition(),
            ObjectDigest::from_bytes([10; 32]),
            hold.binding(),
            hold.epoch(),
        )
        .expect("mismatched head");
        assert!(
            release_closed_policy_cache_hold_at(directory.path(), uid, wrong, || Ok(())).is_err()
        );
        assert_eq!(
            Journal::read_cache_policy_hold_at(directory.path(), uid).expect("retained hold"),
            Some(hold)
        );

        let wrong_partition = CachePolicyHoldV1::new(
            hold.project(),
            ObjectDigest::from_bytes([11; 32]),
            hold.cache_head(),
            hold.binding(),
            hold.epoch(),
        )
        .expect("mismatched partition");
        assert!(
            release_closed_policy_cache_hold_at(directory.path(), uid, wrong_partition, || Ok(()))
                .is_err()
        );

        assert!(
            release_closed_policy_cache_hold_at(directory.path(), uid, hold, || {
                Err(ProtectedDomainJournalErrorV1::StaleAuthority.into())
            })
            .is_err()
        );
        assert_eq!(
            Journal::read_cache_policy_hold_at(directory.path(), uid).expect("retained hold"),
            Some(hold)
        );

        release_closed_policy_cache_hold_at(directory.path(), uid, hold, || {
            assert!(matches!(
                Journal::open_protected_at_uid(
                    directory.path(),
                    CACHE_STATE_JOURNAL,
                    cache_state_journal_limits(),
                    uid,
                ),
                Err(crate::journal::JournalError::AlreadyLocked)
            ));
            assert!(matches!(
                Journal::open_protected_at_uid(
                    directory.path(),
                    CACHE_AUTHORITY_JOURNAL,
                    cache_authority_journal_limits(),
                    uid,
                ),
                Err(crate::journal::JournalError::AlreadyLocked)
            ));
            Ok(())
        })
        .expect("exact offline release after Replay expiry");
        assert!(
            !Journal::read_cache_policy_hold_at(directory.path(), uid)
                .expect("released hold")
                .expect("hold record")
                .is_held()
        );
    }
}
