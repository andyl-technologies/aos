//! Fixed-root ownership for dormant cache-residency durability.
//!
//! The owner opens three independent root-owned journals: cache state, cache
//! authority manifests, and a monotone wall-clock floor. Authority manifests
//! carry the complete checkpoint/floor evidence needed for cold replay. The
//! clock journal prevents a copied or expired manifest from becoming current
//! merely because a process restarted or the wall clock moved backwards.

use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use aos_sandbox_core::{
    AttachmentId, ObjectDescriptor, ObjectDigest, OperationId, ProjectId, ViewId,
};
use sha2::{Digest as _, Sha256};

use crate::journal::{
    Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace, RecoveryReport,
};
use crate::lifecycle::protected_journal_adapter::ProtectedDomainJournalErrorV1;

use super::protected_journal::{
    CacheResidencyCurrentTimeAuthorityV1, CacheResidencyReplayPartitionEvidenceV1,
    ProtectedCacheResidencyReplayAuthorityV1, decode_cache_payload_for_lifecycle,
    decode_partition_descriptor, encode_partition_descriptor,
};
use super::{
    CacheAtomicObjectPayloadV1, CacheAuthorityOwner, CacheAuthorityPurposeV1,
    CacheAuthorityScopeV1, CachePinV1, CacheRecoveryLimitsV1, CacheResidencyAuthorityRequestV1,
    CacheResidencyColdRecoveryV1, CacheResidencyCommitOutcomeV1, CacheResidencyControllerRecordV1,
    CacheResidencyOutcomeUnknownV1, CacheResidencyProtectedJournalEnvelopeV1,
    CacheResidencyProtectedJournalErrorV1, CacheResidencyProtectedJournalProjectionV1,
    CacheResidencyProtectedJournalSnapshotV1, CacheResidencyProtectedJournalV1,
    CacheResidencyProtectedRecordKindV1, CacheResidencyRecoveryV1, CacheResidencyReplayValidatorV1,
    CacheResidencyTransactionKindV1, CacheScrubRecordV1, CacheTypedCheckpointV1,
    EvictionProgressV1, EvictionRetryAuthorityV1, FrozenEvictionPlanV1, PhysicalPartitionId,
    ReclamationEvidenceV1, ReleasedCachePinV1, UnlinkObservationV1,
    ValidatedCacheResidencyPostcommitV1, VerifiedCacheCapabilityV1,
    cache_residency_protected_key_v1, cache_residency_reducer_envelope_v1, decode_floor,
    decode_typed_checkpoint, encode_floor,
};

const PROTECTED_CACHE_ROOT: &str = "/var/lib/aos/sandbox/cache-residency";
const CACHE_STATE_JOURNAL: &str = "state.journal";
const CACHE_AUTHORITY_JOURNAL: &str = "authority.journal";
const CACHE_CLOCK_JOURNAL: &str = "clock.journal";
const CACHE_CLOCK_KEY: &[u8] = b"\0aos-cache-residency-clock-v1\0current";
const CACHE_MANIFEST_KEY_PREFIX: &[u8] = b"\0aos-cache-replay-manifest-v1\0";
const CACHE_MANIFEST_MAGIC: &[u8; 8] = b"AOSCRM01";
const CACHE_CLOCK_MAGIC: &[u8; 8] = b"AOSCCL01";
const CACHE_CLOCK_BYTES: usize = 104;
const CACHE_MANIFEST_FIXED_BYTES: usize = 555;
const MAXIMUM_CACHE_MANIFESTS: usize = 4_096;
const MAXIMUM_AUTHORITY_RECORD_BYTES: usize = 1024 * 1024;

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
        let root = Path::new(PROTECTED_CACHE_ROOT);
        let owner_scope = cache_owner_scope();
        let (clock, clock_report) = ProtectedCacheClockV1::open(root, owner_scope)?;
        let clock: Arc<dyn CacheResidencyCurrentTimeAuthorityV1> = Arc::new(clock);

        let (mut authority_journal, authority_report) = Journal::open_protected_at(
            root,
            CACHE_AUTHORITY_JOURNAL,
            cache_authority_journal_limits(),
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

        let (state_journal, state_report) =
            Journal::open_protected_at(root, CACHE_STATE_JOURNAL, cache_state_journal_limits())?;
        let mut owner = Self {
            state_journal: Some(state_journal),
            authority,
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
        let authority = Arc::clone(&self.authority);
        authority.while_authority_current(&[], |_owner, _capabilities, _now, validator, refresh| {
            let journal = self
                .state_journal
                .as_mut()
                .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            let projection =
                CacheResidencyProtectedJournalV1::claim(journal, validator.clone())?.replay()?;
            let mut latest: Option<(u64, Vec<CachePinV1>)> = None;

            for envelope in projection.records().iter().filter(|envelope| {
                envelope.key().kind() == CacheResidencyProtectedRecordKindV1::Pin
            }) {
                let payload = decode_cache_payload_for_lifecycle(envelope, &validator)?
                    .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
                if payload.plan.partition != partition
                    || &payload.plan.descriptor != object
                    || payload.plan.project != project
                {
                    continue;
                }
                if latest
                    .as_ref()
                    .is_none_or(|(sequence, _)| payload.record.sequence > *sequence)
                {
                    latest = Some((payload.record.sequence, payload.pins));
                }
            }

            let pin = latest.and_then(|(_, pins)| {
                pins.into_iter().find(|pin| {
                    pin.partition == partition
                        && &pin.object == object
                        && pin.project == project
                        && pin.view == view
                        && pin.attachment == attachment
                        && pin.kind == super::CachePinKindV1::LogicalLease
                })
            });
            refresh()?;
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
            let mut latest = BTreeMap::new();
            for envelope in projection.records().iter().filter(|envelope| {
                matches!(
                    envelope.key().kind(),
                    CacheResidencyProtectedRecordKindV1::Reservation
                        | CacheResidencyProtectedRecordKindV1::Pin
                        | CacheResidencyProtectedRecordKindV1::Catalog
                )
            }) {
                let payload = decode_cache_payload_for_lifecycle(envelope, &validator)?
                    .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
                // The same object may have independent obligations in multiple partitions.
                let key = (
                    envelope.key().kind(),
                    payload.record.partition,
                    payload.record.subject,
                );
                match latest.get(&key) {
                    Some((sequence, _, _)) if *sequence >= payload.record.sequence => {}
                    _ => {
                        latest.insert(key, (payload.record.sequence, envelope.digest(), payload));
                    }
                }
            }

            let mut entries = Vec::new();
            for ((kind, _, _), (_, _envelope, payload)) in latest {
                match kind {
                    CacheResidencyProtectedRecordKindV1::Reservation
                        if matches!(
                            payload.reservation.state,
                            super::ReservationStateV1::Reserved
                                | super::ReservationStateV1::Uncertain
                        ) =>
                    {
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
                    CacheResidencyProtectedRecordKindV1::Catalog => {
                        if let Some(catalog) = payload
                            .catalog
                            .filter(|catalog| catalog.presence != super::CatalogPresenceV1::Evicted)
                        {
                            let mut environment = [0_u8; 16];
                            environment
                                .copy_from_slice(&catalog.descriptor.digest().as_bytes()[..16]);
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
                    }
                    CacheResidencyProtectedRecordKindV1::Pin => {
                        for pin in payload.pins {
                            let resource = if let Some(attachment) = pin.attachment {
                                crate::lifecycle::LifecycleResourceV1::Attachment(
                                    aos_sandbox_core::ResourceId::from_bytes(
                                        *attachment.as_bytes(),
                                    ),
                                )
                            } else {
                                crate::lifecycle::LifecycleResourceV1::View(pin.view)
                            };
                            // Physical obligations remain distinct across disclosure partitions.
                            let identity = ObjectDigest::from_bytes(
                                Sha256::new()
                                    .chain_update(
                                        b"aos.sandbox.lifecycle.cache-pin-physical-row.v2\0",
                                    )
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
                    _ => {}
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

    /// Reopens protected state and classifies one exact ambiguous transition.
    ///
    /// # Errors
    ///
    /// Returns an error when protected reopen or complete typed replay fails.
    pub fn recover<R>(
        &mut self,
        pending: CacheResidencyOutcomeUnknownV1,
        handoff: impl for<'current> FnOnce(ValidatedCacheResidencyPostcommitV1<'current>) -> R,
    ) -> Result<(CacheResidencyRecoveryV1, Option<R>), CacheResidencyProtectedJournalErrorV1> {
        self.reopen_state()?;
        let authority = Arc::clone(&self.authority);
        authority.while_authority_current(&[], |_owner, _capabilities, _now, validator, refresh| {
            let journal = self
                .state_journal
                .as_mut()
                .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            let journal = CacheResidencyProtectedJournalV1::claim(journal, validator)?;
            let mut recovery = journal.recover(pending)?;
            let handoff_result = match &mut recovery {
                CacheResidencyRecoveryV1::Applied(applied) => {
                    if refresh().is_err() {
                        return Ok((recovery, None));
                    }
                    let Some(capability) = applied.take_postcommit() else {
                        return Ok((recovery, None));
                    };
                    let validated = capability.consume(&journal)?;
                    Some(handoff(validated))
                }
                CacheResidencyRecoveryV1::Retry(_)
                | CacheResidencyRecoveryV1::Diverged(_)
                | CacheResidencyRecoveryV1::Indeterminate { .. } => None,
            };
            Ok((recovery, handoff_result))
        })
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

    fn reopen_state(&mut self) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        drop(self.state_journal.take());
        let (journal, _) = Journal::open_protected_at(
            Path::new(PROTECTED_CACHE_ROOT),
            CACHE_STATE_JOURNAL,
            cache_state_journal_limits(),
        )?;
        self.state_journal = Some(journal);
        Ok(())
    }
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
    ) -> Result<(Self, RecoveryReport), CacheResidencyProtectedJournalErrorV1> {
        let (mut journal, report) =
            Journal::open_protected_at(root, CACHE_CLOCK_JOURNAL, cache_clock_journal_limits())?;
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
                let (reopened, applied) = persist_cache_clock(journal, None, genesis)?;
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
        let (reopened, applied) = persist_cache_clock(journal, Some(state.floor), successor)?;
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

    let (mut reopened, _) = Journal::open_protected_at(
        Path::new(PROTECTED_CACHE_ROOT),
        CACHE_CLOCK_JOURNAL,
        cache_clock_journal_limits(),
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

fn decode_cache_replay_manifest(
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

fn encode_cache_replay_manifest(
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
