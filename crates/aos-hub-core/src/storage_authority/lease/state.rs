//! Pure issuer journals, local floors and bounded lease-admission cutoffs.

use std::future::Future;

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use super::wire::{contains, digest, key, prefix};
use super::{
    EpochLeasePayload, EpochLeaseSigningKey, EpochLeaseVerifier, LeaseCohort, LeaseEffect,
    LeaseInteger, LeaseTimingProfile,
};
use crate::storage_authority::{
    canonical_digest, control::StorageAuthorityPublication, CreatePhysicalStorageAuthority,
    StorageAuthorityAdmissionState,
};

/// Trusted adapter observation with an explicitly qualified uncertainty bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseClock {
    /// Observed Unix seconds; the adapter must detect clock rollback.
    pub observed_at: i64,
    /// Qualified absolute uncertainty, in seconds.
    pub uncertainty: i64,
}

impl LeaseClock {
    pub(super) fn bounds(
        self,
        profile: &LeaseTimingProfile,
        floor: LeaseInteger,
    ) -> Result<(i64, i64)> {
        profile.validate()?;
        ensure!(
            self.observed_at >= floor.get()
                && self.uncertainty >= 0
                && self.uncertainty <= profile.maximum_clock_uncertainty.get(),
            "unqualified or rolled-back clock"
        );
        let lower = self
            .observed_at
            .checked_sub(self.uncertainty)
            .ok_or_else(|| anyhow::anyhow!("clock underflow"))?;
        let upper = self
            .observed_at
            .checked_add(self.uncertainty)
            .ok_or_else(|| anyhow::anyhow!("clock overflow"))?;
        ensure!(lower >= 0, "indeterminate negative clock bound");
        Ok((lower, upper))
    }
}

/// Explicit bounded-revocation policy, distinct from immediate BeginDispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedLeaseRevocationPolicy {
    /// Caller-reviewed exact timing profile.
    pub timing_profile: LeaseTimingProfile,
}

impl BoundedLeaseRevocationPolicy {
    /// Tests only closure of the old lease admission window.
    ///
    /// A true result proves neither provider drain nor safe receipt retirement.
    /// Inputs must come from the exact retained live issuer journal under its
    /// serialized denial gate; archived SQL or estimated expiry is insufficient.
    /// Caller persists the returned observation floor before acting on it.
    ///
    /// # Errors
    /// Returns an error for unqualified, rolled-back or overflowing time.
    pub fn admission_cutoff(
        &self,
        largest_issued_expiry: LeaseInteger,
        clock_floor: LeaseInteger,
        clock: LeaseClock,
    ) -> Result<LeaseAdmissionCutoff> {
        let (earliest, _) = clock.bounds(&self.timing_profile, clock_floor)?;
        Ok(LeaseAdmissionCutoff {
            reached: earliest >= largest_issued_expiry.get(),
            next_clock_floor: LeaseInteger::new(clock.observed_at)?,
        })
    }
}

/// Lease admission cutoff only; never an authority-wide provider-drain receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseAdmissionCutoff {
    /// Whether no prior lease can pass the bounded admission time check.
    pub reached: bool,
    /// Observation floor the caller must persist atomically with its decision.
    pub next_clock_floor: LeaseInteger,
}

/// Exact durable issuer journal; callers supply actual live persistence.
///
/// Restoring this journal backwards or initializing an already-used namespace
/// from archived SQL is unsupported. Field access supports adapters, not proof
/// of freshness. All issuance and denial must share one serialized live gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochLeaseIssuerJournal {
    /// Permanent qualified authority facts.
    pub authority: CreatePhysicalStorageAuthority,
    /// Permanent configured executor.
    pub executor_identity: String,
    /// Exact current publication generation.
    pub generation: LeaseInteger,
    /// Exact current admission digest.
    pub admission_digest: String,
    /// Exact entire-publication digest.
    pub publication_digest: String,
    /// Current issuance state; retirement is terminal.
    pub state: StorageAuthorityAdmissionState,
    /// Explicit reviewed bounded-revocation policy.
    pub policy: BoundedLeaseRevocationPolicy,
    /// Authority-wide sequence, never reset on epoch advance.
    pub last_sequence: LeaseInteger,
    /// Largest committed token expiry, retained even if response is lost.
    pub largest_issued_expiry: LeaseInteger,
    /// Monotonic observed time floor.
    pub clock_floor: LeaseInteger,
}

impl EpochLeaseIssuerJournal {
    /// Initializes a freshly qualified, never-used issuer namespace.
    ///
    /// The live adapter must prove namespace novelty and a verified publication;
    /// this pure constructor cannot do either. It deliberately refuses later
    /// generations, rather than bootstrap an existing namespace from SQL.
    ///
    /// # Errors
    /// Returns an error for malformed publication/profile/time or a noninitial
    /// generation. This constructor is not a recovery operation.
    pub fn initialize_fresh_namespace(
        publication: &StorageAuthorityPublication,
        executor: &str,
        policy: BoundedLeaseRevocationPolicy,
        clock: LeaseClock,
    ) -> Result<Self> {
        publication.validate(&publication.authority.guard_namespace_id, executor)?;
        ensure!(
            publication.generation == 1 && publication.admission.expected_generation == 0,
            "used namespace requires retained issuer journal"
        );
        clock.bounds(&policy.timing_profile, LeaseInteger::new(0)?)?;
        Ok(Self {
            authority: publication.authority.clone(),
            executor_identity: executor.to_owned(),
            generation: LeaseInteger::new(publication.generation)?,
            admission_digest: publication.digest.clone(),
            publication_digest: canonical_digest(publication)?,
            state: publication.admission.state,
            policy,
            last_sequence: LeaseInteger::new(0)?,
            largest_issued_expiry: LeaseInteger::new(0)?,
            clock_floor: LeaseInteger::new(clock.observed_at)?,
        })
    }

    /// Validates restored structural invariants without proving live provenance.
    ///
    /// # Errors
    /// Returns an error for malformed permanent identity, policy or issuance history.
    pub fn validate(&self) -> Result<()> {
        self.authority.validate()?;
        key(&self.executor_identity, 255)?;
        ensure!(
            self.generation.get() > 0
                && self.generation.get()
                    <= crate::storage_authority::control::MAX_AUTHORITY_GENERATION,
            "invalid journal generation"
        );
        digest(&self.admission_digest)?;
        digest(&self.publication_digest)?;
        self.policy.timing_profile.validate()?;
        ensure!(
            (self.last_sequence.get() == 0) == (self.largest_issued_expiry.get() == 0),
            "expiry without issuance history"
        );
        Ok(())
    }

    /// Prepares a live publication/denial CAS retaining issuance history.
    ///
    /// Reopening or replacing an admitted epoch requires prior denial and
    /// confirmed bounded lease cutoff. It never clears object unknown fences.
    /// A real adapter must verify root publication/registry provenance and
    /// persist this transition under the same gate as lease issuance.
    ///
    /// # Errors
    /// Returns an error for retirement, identity change, stale/forked predecessor,
    /// unqualified time, or premature reopening.
    pub fn prepare_publication(
        &self,
        publication: &StorageAuthorityPublication,
        clock: LeaseClock,
    ) -> Result<IssuerTransition> {
        self.validate()?;
        publication.validate(&self.authority.guard_namespace_id, &self.executor_identity)?;
        ensure!(
            publication.authority == self.authority,
            "permanent authority facts changed"
        );
        ensure!(
            self.state != StorageAuthorityAdmissionState::Retired,
            "retirement is terminal"
        );
        ensure!(
            publication.admission.expected_generation == self.generation.get()
                && publication.admission.expected_digest.as_deref()
                    == Some(self.admission_digest.as_str()),
            "publication predecessor is stale or forked"
        );
        let cutoff =
            self.policy
                .admission_cutoff(self.largest_issued_expiry, self.clock_floor, clock)?;
        if publication.admission.state == StorageAuthorityAdmissionState::Admitted {
            ensure!(
                self.state == StorageAuthorityAdmissionState::Blocked && cutoff.reached,
                "prior denial and lease cutoff required for admission"
            );
            let (_, latest) = clock.bounds(&self.policy.timing_profile, self.clock_floor)?;
            publication.validate_admission_time(latest)?;
        }

        let mut next = self.clone();
        next.generation = LeaseInteger::new(publication.generation)?;
        next.admission_digest = publication.digest.clone();
        next.publication_digest = canonical_digest(publication)?;
        next.state = publication.admission.state;
        next.clock_floor = cutoff.next_clock_floor;
        Ok(IssuerTransition {
            expected: self.clone(),
            next,
        })
    }

    /// Prepares a denied-only jump from the exact retained live predecessor.
    ///
    /// The adapter verifies registry provenance and compares this complete journal
    /// atomically. SQL history remains unchanged; skipped admission is never replayed.
    /// Retirement, committed expiry and sequence remain permanent.
    ///
    /// # Errors
    /// Returns an error for admitted input, identity changes, rollback, conflicting
    /// SQL predecessor or terminal retirement.
    pub fn prepare_denied_gap(
        &self,
        transition: &crate::storage_authority::control::StorageAuthorityDeniedTransition,
        clock: LeaseClock,
    ) -> Result<IssuerTransition> {
        self.validate()?;
        transition.validate(&self.authority.guard_namespace_id, &self.executor_identity)?;
        let publication = &transition.publication;
        ensure!(
            publication.authority == self.authority,
            "permanent authority changed"
        );
        ensure!(
            self.state != StorageAuthorityAdmissionState::Retired,
            "retirement is terminal"
        );
        let remote = transition
            .expected_remote
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("existing issuer requires exact predecessor"))?;
        ensure!(
            remote.generation == self.generation.get() && remote.digest == self.admission_digest,
            "denial live predecessor differs"
        );
        ensure!(
            publication.generation > self.generation.get(),
            "denial cannot roll back"
        );
        ensure!(
            publication.admission.expected_generation != self.generation.get()
                || publication.admission.expected_digest.as_deref()
                    == Some(self.admission_digest.as_str()),
            "denial crosses conflicting SQL predecessor"
        );
        let cutoff =
            self.policy
                .admission_cutoff(self.largest_issued_expiry, self.clock_floor, clock)?;
        let mut next = self.clone();
        next.generation = LeaseInteger::new(publication.generation)?;
        next.admission_digest = publication.digest.clone();
        next.publication_digest = canonical_digest(publication)?;
        next.state = publication.admission.state;
        next.clock_floor = cutoff.next_clock_floor;
        Ok(IssuerTransition {
            expected: self.clone(),
            next,
        })
    }

    /// Prepares unsigned issuance from the exact verified live admitted head.
    ///
    /// The caller must execute this inside the actual live issuer serialization
    /// boundary, with a verified current publication. Merely reading archived
    /// SQL or constructing these DTOs is insufficient. No signed bytes are
    /// available until `PreparedEpochLease::commit_and_sign` succeeds.
    ///
    /// # Errors
    /// Returns an error for denied/stale/forked publication, mismatched cohort,
    /// expired evidence, invalid time, invalid lifetime or exhausted sequence.
    pub fn prepare_issue(
        &self,
        publication: &StorageAuthorityPublication,
        cohort: LeaseCohort,
        issuer_key_id: &str,
        requested_not_after: i64,
        clock: LeaseClock,
    ) -> Result<PreparedEpochLease> {
        self.validate()?;
        ensure!(
            self.state == StorageAuthorityAdmissionState::Admitted,
            "issuer is denied"
        );
        publication.validate(&self.authority.guard_namespace_id, &self.executor_identity)?;
        ensure!(
            publication.authority == self.authority
                && publication.generation == self.generation.get()
                && publication.digest == self.admission_digest
                && canonical_digest(publication)? == self.publication_digest
                && publication.admission.state == self.state,
            "publication is not exact live journal head"
        );
        let selected = LeaseCohort::from_publication(
            publication,
            &self.executor_identity,
            &cohort.association.association_id,
            cohort.credential.purpose,
            &cohort.admitted_prefix,
            cohort.allowed_effects.clone(),
        )?;
        ensure!(selected == cohort, "cohort differs from exact publication");
        let (_, latest) = clock.bounds(&self.policy.timing_profile, self.clock_floor)?;
        publication.validate_admission_time(latest)?;
        key(issuer_key_id, 255)?;
        let lifetime_ceiling = clock
            .observed_at
            .checked_add(self.policy.timing_profile.maximum_lifetime.get())
            .ok_or_else(|| anyhow::anyhow!("expiry overflow"))?;
        let attestation = publication
            .attestation
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing attestation"))?;
        let expiry = requested_not_after
            .min(lifetime_ceiling)
            .min(attestation.valid_until);
        ensure!(expiry > latest, "lease has no safe lifetime");
        let sequence = self
            .last_sequence
            .get()
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("lease sequence exhausted"))?;
        let payload = EpochLeasePayload {
            protocol_version: 1,
            issuer_key_id: issuer_key_id.to_owned(),
            cohort,
            timing_profile: self.policy.timing_profile.clone(),
            issued_at: LeaseInteger::new(clock.observed_at)?,
            not_after: LeaseInteger::new(expiry)?,
            lease_sequence: LeaseInteger::new(sequence)?,
        };
        payload.validate()?;
        let mut next = self.clone();
        next.last_sequence = payload.lease_sequence;
        next.largest_issued_expiry =
            LeaseInteger::new(self.largest_issued_expiry.get().max(expiry))?;
        next.clock_floor = payload.issued_at;
        Ok(PreparedEpochLease {
            payload,
            transition: IssuerTransition {
                expected: self.clone(),
                next,
            },
        })
    }
}

/// Exact atomic journal compare-and-swap requested from the live adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerTransition {
    /// Exact expected journal, including current publication commitment.
    pub expected: EpochLeaseIssuerJournal,
    /// Exact replacement, including retained sequence and largest expiry.
    pub next: EpochLeaseIssuerJournal,
}

/// Private unsigned prepared lease, with no token or signing accessor.
#[derive(Debug)]
pub struct PreparedEpochLease {
    payload: EpochLeasePayload,
    transition: IssuerTransition,
}

impl PreparedEpochLease {
    /// Exposes the exact journal transition for adapter inspection.
    pub fn transition(&self) -> &IssuerTransition {
        &self.transition
    }

    /// Commits issuance durably, signs, rechecks time, then commits its floor.
    ///
    /// `persist` must atomically compare the complete `expected` live journal
    /// and publication with the actual durable current state and persist `next`
    /// before acknowledging success. Owned transitions support actual async
    /// Worker storage adapters. The helper awaits each acknowledgment; the
    /// callback MUST NOT substitute cached/precommitted success for actual live
    /// durable CAS. This helper cannot establish callback provenance/durability.
    /// It is invoked twice: issuance before signing,
    /// then a clock-floor CAS before returning usable bytes. Both must serialize
    /// with denial. The pure helper cannot prove a callback actually does this.
    /// The second CAS also refuses a denial that won after initial issuance.
    ///
    /// The clock adapter must detect rollback across every observation, including
    /// failed/unpersisted observations. A final observation after the last CAS
    /// checks time again immediately before bytes return; the prior observation
    /// is retained durably, and the adapter owns the final clock continuity.
    /// Failure after the first commit conservatively consumes sequence/expiry;
    /// it must never roll back that commit. Lost returned bytes remain included
    /// in the denial cutoff. Issuer secrets must be unavailable to Native and
    /// executors. This method provides no live issuer or provider dispatch.
    ///
    /// Cancellation while either acknowledgment is pending returns no token.
    /// A possibly committed write must retain its sequence/expiry even when the
    /// caller cancels or loses the acknowledgment; this helper performs no undo.
    ///
    /// # Errors
    /// Returns an error for wrong key, either persistence/CAS failure, signing
    /// failure, or expiry/rollback/uncertainty during the final observation.
    pub async fn commit_and_sign<PersistFuture>(
        self,
        signer: &EpochLeaseSigningKey,
        mut persist: impl FnMut(IssuerTransition) -> PersistFuture,
        mut observe_clock: impl FnMut() -> Result<LeaseClock>,
    ) -> Result<Vec<u8>>
    where
        PersistFuture: Future<Output = Result<()>>,
    {
        ensure!(
            signer.key_id() == self.payload.issuer_key_id,
            "issuer key mismatch"
        );
        let committed = self.transition.next.clone();
        persist(self.transition).await?;
        let bytes = signer.sign(self.payload.clone())?;
        let clock = observe_clock()?;
        validate_time(&self.payload, committed.clock_floor, clock)?;
        let mut next = committed.clone();
        next.clock_floor = LeaseInteger::new(clock.observed_at)?;
        let final_floor = next.clock_floor;
        persist(IssuerTransition {
            expected: committed,
            next,
        })
        .await?;
        validate_time(&self.payload, final_floor, observe_clock()?)?;
        Ok(bytes)
    }
}

/// Durable per-object epoch/time floors and maximum observed issuance witness.
///
/// Concurrent authentic tokens remain reusable within one admitted epoch. The
/// sequence witness detects forks at the retained maximum, not every forgotten
/// lower sequence. Unique irreversible issuance still requires the live issuer
/// journal and its actual durable CAS; SQL cannot initialize or rewind it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochLeaseFloor {
    /// Permanent authority creation facts.
    pub authority: CreatePhysicalStorageAuthority,
    /// Configured immutable executor.
    pub executor_identity: String,
    /// Exact permanent full physical key selecting this guard.
    pub full_key: String,
    /// Largest observed epoch, zero only for a freshly qualified guard.
    pub generation: LeaseInteger,
    /// Admission digest, absent only before observing an epoch.
    pub admission_digest: Option<String>,
    /// Entire-publication digest, absent only before observing an epoch.
    pub publication_digest: Option<String>,
    /// Largest observed authority-wide sequence, not a same-epoch token cutoff.
    pub lease_sequence: LeaseInteger,
    /// Exact payload digest at the maximum; lower-token digests are not retained.
    pub payload_digest: Option<String>,
    /// Whether a trusted live denied publication forbids this epoch.
    pub denied: bool,
    /// Terminal retirement, retained even if a later token is correctly signed.
    pub retired: bool,
    /// Largest retained observed clock value.
    pub clock_floor: LeaseInteger,
}

impl EpochLeaseFloor {
    /// Initializes a newly qualified guard within an existing permanent domain.
    ///
    /// This does not prove the guard is fresh and must not reset a used guard.
    ///
    /// # Errors
    /// Returns an error for malformed permanent facts, executor, profile or time.
    pub fn initialize_fresh_guard(
        authority: CreatePhysicalStorageAuthority,
        executor: String,
        full_key: String,
        profile: &LeaseTimingProfile,
        clock: LeaseClock,
    ) -> Result<Self> {
        authority.validate()?;
        key(&executor, 255)?;
        prefix(&full_key, 1024)?;
        ensure!(
            !full_key.is_empty() && contains(&full_key, &authority.qualified_managed_prefix),
            "guard key exceeds permanent scope"
        );
        clock.bounds(profile, LeaseInteger::new(0)?)?;
        Ok(Self {
            authority,
            executor_identity: executor,
            full_key,
            generation: LeaseInteger::new(0)?,
            admission_digest: None,
            publication_digest: None,
            lease_sequence: LeaseInteger::new(0)?,
            payload_digest: None,
            denied: false,
            retired: false,
            clock_floor: LeaseInteger::new(clock.observed_at)?,
        })
    }

    fn validate(&self) -> Result<()> {
        self.authority.validate()?;
        key(&self.executor_identity, 255)?;
        prefix(&self.full_key, 1024)?;
        ensure!(
            !self.full_key.is_empty()
                && contains(&self.full_key, &self.authority.qualified_managed_prefix),
            "guard key exceeds permanent scope"
        );
        ensure!(
            self.generation.get() <= crate::storage_authority::control::MAX_AUTHORITY_GENERATION,
            "invalid floor generation"
        );
        ensure!(
            (self.generation.get() == 0) == self.admission_digest.is_none()
                && self.admission_digest.is_none() == self.publication_digest.is_none(),
            "incomplete epoch floor"
        );
        if let Some(value) = &self.admission_digest {
            digest(value)?;
        }
        if let Some(value) = &self.publication_digest {
            digest(value)?;
        }
        ensure!(
            (self.lease_sequence.get() == 0) == self.payload_digest.is_none(),
            "incomplete sequence floor"
        );
        if let Some(value) = &self.payload_digest {
            digest(value)?;
        }
        ensure!(
            self.generation.get() > 0 || self.lease_sequence.get() == 0,
            "sequence without observed epoch"
        );
        ensure!(!self.retired || self.denied, "retirement without denial");
        ensure!(
            !self.denied || self.generation.get() > 0,
            "denial without observed epoch"
        );
        Ok(())
    }

    /// Prepares a floor from an independently authenticated live denied head.
    ///
    /// This accepts no unauthenticated push event. A later protocol must verify
    /// its own distinct denial signature domain and actual authority provenance.
    /// The caller must persist the returned floor before relying on denial.
    ///
    /// # Errors
    /// Returns an error for an admitted, lower/forked or mismatched publication.
    pub fn observe_trusted_denial(
        &self,
        publication: &StorageAuthorityPublication,
        profile: &LeaseTimingProfile,
        clock: LeaseClock,
    ) -> Result<Self> {
        self.validate()?;
        publication.validate(&self.authority.guard_namespace_id, &self.executor_identity)?;
        ensure!(
            publication.authority == self.authority
                && publication.admission.state != StorageAuthorityAdmissionState::Admitted,
            "not a matching denied head"
        );
        ensure!(
            !self.retired
                || (publication.admission.state == StorageAuthorityAdmissionState::Retired
                    && publication.generation == self.generation.get()),
            "retirement is terminal"
        );
        let pub_digest = canonical_digest(publication)?;
        self.check_epoch(publication.generation, &publication.digest, &pub_digest)?;
        clock.bounds(profile, self.clock_floor)?;
        let mut next = self.clone();
        next.generation = LeaseInteger::new(publication.generation)?;
        next.admission_digest = Some(publication.digest.clone());
        next.publication_digest = Some(pub_digest);
        next.denied = true;
        next.retired = publication.admission.state == StorageAuthorityAdmissionState::Retired;
        next.clock_floor = LeaseInteger::new(clock.observed_at)?;
        Ok(next)
    }

    fn check_epoch(&self, generation: i64, admission: &str, publication: &str) -> Result<()> {
        ensure!(
            generation >= self.generation.get(),
            "lease epoch below local floor"
        );
        if generation == self.generation.get() {
            ensure!(
                self.admission_digest.as_deref() == Some(admission)
                    && self.publication_digest.as_deref() == Some(publication),
                "same-generation publication fork"
            );
        }
        Ok(())
    }
}

/// Pure validated payload and proposed durable local floor, without readiness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedEpochLease {
    /// Authenticated exact payload.
    pub payload: EpochLeasePayload,
    /// Caller must persist this before new dispatch admission.
    pub next_floor: EpochLeaseFloor,
}

impl EpochLeaseVerifier {
    /// Authenticates exact cohort/time/effect/key against a retained local floor.
    ///
    /// `expected` is an independently verified immutable snapshot, not facts
    /// extracted from this token. `profile` is independently configured. This
    /// accepts a never-seen guard's authentic unexpired old epoch within the
    /// explicitly reviewed bounded-revocation window; it proves no fresh global
    /// state. Callers must retain unknown intent, require independent application
    /// authorization/grants and persist the returned floor/intent before I/O.
    /// They must recheck expiry immediately at actual invocation, with no await
    /// between that check and provider call. Runtime continuation must qualify
    /// that boundary. This pure method invokes no provider and settles nothing.
    ///
    /// # Errors
    /// Returns an error for malformed/untrusted envelope, snapshot/profile/key/
    /// effect mismatch, stale/forked epoch, a fork at the retained maximum
    /// sequence, issuance rollback across epochs, denial or invalid time.
    pub fn validate_lease(
        &self,
        bytes: &[u8],
        expected: &LeaseCohort,
        profile: &LeaseTimingProfile,
        floor: &EpochLeaseFloor,
        full_key: &str,
        effect: LeaseEffect,
        clock: LeaseClock,
    ) -> Result<ValidatedEpochLease> {
        floor.validate()?;
        ensure!(!floor.retired, "retirement is terminal");
        expected.validate()?;
        profile.validate()?;
        let payload = self.verify(bytes)?;
        ensure!(
            payload.cohort == *expected && payload.timing_profile == *profile,
            "immutable cohort or pinned time profile mismatch"
        );
        ensure!(
            payload.cohort.authority == floor.authority
                && payload.cohort.executor_identity == floor.executor_identity,
            "permanent floor domain mismatch"
        );
        prefix(full_key, 1024)?;
        ensure!(
            full_key == floor.full_key
                && !full_key.is_empty()
                && contains(full_key, &expected.admitted_prefix)
                && expected.allowed_effects.contains(&effect),
            "key or effect exceeds cohort scope"
        );
        floor.check_epoch(
            expected.admission_generation.get(),
            &expected.admission_digest,
            &expected.publication_digest,
        )?;
        ensure!(
            !(floor.denied && expected.admission_generation == floor.generation),
            "epoch locally denied"
        );
        let commitment = payload.digest()?;
        // Issuing another token does not revoke still-valid tokens in the same
        // exact epoch. Across epochs, retain the observable issuer rollback
        // check without keeping an unbounded map of cohort/token histories.
        if expected.admission_generation > floor.generation {
            ensure!(
                payload.lease_sequence > floor.lease_sequence,
                "new epoch sequence does not advance retained maximum"
            );
        }
        if payload.lease_sequence == floor.lease_sequence {
            ensure!(
                floor.payload_digest.as_deref() == Some(commitment.as_str()),
                "same-sequence lease fork"
            );
        }
        validate_time(&payload, floor.clock_floor, clock)?;

        let mut next = floor.clone();
        next.generation = expected.admission_generation;
        next.admission_digest = Some(expected.admission_digest.clone());
        next.publication_digest = Some(expected.publication_digest.clone());
        if payload.lease_sequence > floor.lease_sequence {
            next.lease_sequence = payload.lease_sequence;
            next.payload_digest = Some(commitment);
        }
        next.denied = false;
        next.clock_floor = LeaseInteger::new(clock.observed_at)?;
        Ok(ValidatedEpochLease {
            payload,
            next_floor: next,
        })
    }
}

pub(super) fn validate_time(
    payload: &EpochLeasePayload,
    floor: LeaseInteger,
    clock: LeaseClock,
) -> Result<()> {
    let (_, latest) = clock.bounds(&payload.timing_profile, floor)?;
    ensure!(
        payload.issued_at.get() <= latest && latest < payload.not_after.get(),
        "lease not yet valid or expired under qualified uncertainty"
    );
    Ok(())
}
