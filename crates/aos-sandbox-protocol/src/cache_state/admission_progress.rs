//! Passive immutable-publication progress and watermark DATA reducers.
//!
//! These records describe historical stages. Their constructors and adjacent
//! transitions neither perform an effect nor grant current Cache authority.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::CacheReservationId;

/// Selects the closed immutable-publication effect sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AdmissionStageV1 {
    /// Capacity and immutable plan are durable; no allocation occurred.
    Reserved = 1,
    /// A fresh private destination was created beneath protected root custody.
    PrivateDestinationCreated = 2,
    /// Exact bounded source bytes were transferred into the private destination.
    ContentTransferred = 3,
    /// Digest, size, media type, source, and tree relationship were verified.
    ContentVerified = 4,
    /// Every writable description was authoritatively closed.
    WritersClosed = 5,
    /// Immutability was enabled and its exact measurement re-observed.
    SealEnabledAndVerified = 6,
    /// The immutable destination inode or snapshot was durably synchronized.
    InodeSynced = 7,
    /// Canonical naming completed with no-replace semantics.
    CanonicalNamePublished = 8,
    /// The canonical parent directory was durably synchronized.
    ParentSynced = 9,
    /// Catalog visibility, pins, and residency accounting committed atomically.
    CatalogCommitted = 10,
    /// Interruption left the exact physical effect outcome unknown.
    Uncertain = 11,
    /// A mismatched artifact was isolated from consumers.
    Quarantined = 12,
    /// A proved pre-effect or safely removed artifact released its reservation.
    Aborted = 13,
}

/// Tracks exact immutable-publication progress without granting effect authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionProgressV1 {
    /// Exact immutable admission plan.
    pub plan_digest: ObjectDigest,
    /// Current closed publication stage.
    pub stage: AdmissionStageV1,
    /// Last non-uncertain stage, used to prevent recovery rollback.
    pub last_certain_stage: AdmissionStageV1,
    /// Monotone progress generation.
    pub generation: u64,
    /// Exact predecessor progress digest, absent only at generation one.
    pub predecessor: Option<ObjectDigest>,
    /// Trusted effect or observation evidence for this stage.
    pub evidence: ObjectDigest,
    /// Digest of this complete progress record.
    pub digest: ObjectDigest,
}

impl AdmissionProgressV1 {
    /// Constructs the no-effect durable state for an admitted plan.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionProgressErrorV1`] for sentinel plan/evidence.
    pub fn reserved(
        plan_digest: ObjectDigest,
        admission_evidence: ObjectDigest,
    ) -> Result<Self, AdmissionProgressErrorV1> {
        let mut progress = Self {
            plan_digest,
            stage: AdmissionStageV1::Reserved,
            last_certain_stage: AdmissionStageV1::Reserved,
            generation: 1,
            predecessor: None,
            evidence: admission_evidence,
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        progress.digest = admission_progress_digest(&progress);
        progress.validate()?;
        Ok(progress)
    }

    /// Advances one exact adjacent publication stage.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionProgressErrorV1`] for non-adjacent, terminal,
    /// or evidence-free transitions.
    pub fn advance(
        &self,
        next_stage: AdmissionStageV1,
        evidence: ObjectDigest,
    ) -> Result<Self, AdmissionProgressErrorV1> {
        if self.stage == AdmissionStageV1::Uncertain
            || stage_rank(next_stage) != stage_rank(self.stage).saturating_add(1)
            || stage_rank(next_stage) > stage_rank(AdmissionStageV1::ParentSynced)
        {
            return Err(AdmissionProgressErrorV1);
        }
        self.successor(next_stage, next_stage, evidence)
    }

    /// Marks an entered effect as ambiguous without releasing capacity.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionProgressErrorV1`] for no-effect or terminal
    /// states and sentinel evidence.
    pub fn mark_uncertain(&self, evidence: ObjectDigest) -> Result<Self, AdmissionProgressErrorV1> {
        if matches!(
            self.stage,
            AdmissionStageV1::Reserved
                | AdmissionStageV1::CatalogCommitted
                | AdmissionStageV1::Uncertain
                | AdmissionStageV1::Quarantined
                | AdmissionStageV1::Aborted
        ) {
            return Err(AdmissionProgressErrorV1);
        }
        self.successor(AdmissionStageV1::Uncertain, self.stage, evidence)
    }

    /// Resolves ambiguity from fresh exact physical observation.
    ///
    /// Recovery may retain or advance the last certain stage, quarantine a
    /// mismatch, or prove an abort. It may not move physical history backwards
    /// or declare catalog commitment on its own.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionProgressErrorV1`] for an unsafe resolution.
    pub fn resolve_uncertainty(
        &self,
        observed_stage: AdmissionStageV1,
        evidence: ObjectDigest,
    ) -> Result<Self, AdmissionProgressErrorV1> {
        if self.stage != AdmissionStageV1::Uncertain
            || observed_stage == AdmissionStageV1::Uncertain
            || observed_stage == AdmissionStageV1::CatalogCommitted
            || (stage_rank(observed_stage) < stage_rank(self.last_certain_stage)
                && !matches!(
                    observed_stage,
                    AdmissionStageV1::Quarantined | AdmissionStageV1::Aborted
                ))
        {
            return Err(AdmissionProgressErrorV1);
        }
        self.successor(observed_stage, observed_stage, evidence)
    }

    /// Terminates before catalog commit after proving no reachable artifact remains.
    ///
    /// Reserved progress needs only a no-effect decision. Any later stage needs
    /// authoritative cleanup/absence evidence; the evidence digest is retained.
    /// Uncertain progress may abort only after recovery establishes absence.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionProgressErrorV1`] after catalog commit or from
    /// an already terminal state.
    #[doc(hidden)]
    pub fn abort(&self, absence_evidence: ObjectDigest) -> Result<Self, AdmissionProgressErrorV1> {
        if matches!(
            self.stage,
            AdmissionStageV1::CatalogCommitted
                | AdmissionStageV1::Quarantined
                | AdmissionStageV1::Aborted
        ) {
            return Err(AdmissionProgressErrorV1);
        }
        self.successor(
            AdmissionStageV1::Aborted,
            AdmissionStageV1::Aborted,
            absence_evidence,
        )
    }

    /// Computes the committed progress DATA after the adjacent parent-sync stage.
    ///
    /// This reducer does not commit a catalog or authorize publication.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionProgressErrorV1`] unless the prior stage is ParentSynced.
    #[doc(hidden)]
    pub fn catalog_committed(&self, evidence: ObjectDigest) -> Result<Self, AdmissionProgressErrorV1> {
        if self.stage != AdmissionStageV1::ParentSynced {
            return Err(AdmissionProgressErrorV1);
        }
        self.successor(
            AdmissionStageV1::CatalogCommitted,
            AdmissionStageV1::CatalogCommitted,
            evidence,
        )
    }

    fn successor(
        &self,
        stage: AdmissionStageV1,
        last_certain_stage: AdmissionStageV1,
        evidence: ObjectDigest,
    ) -> Result<Self, AdmissionProgressErrorV1> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(AdmissionProgressErrorV1)?;
        let mut next = Self {
            plan_digest: self.plan_digest,
            stage,
            last_certain_stage,
            generation,
            predecessor: Some(self.digest),
            evidence,
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        next.digest = admission_progress_digest(&next);
        next.validate()?;
        Ok(next)
    }

    /// Validates the closed progress shape and canonical commitment.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionProgressErrorV1`] for a malformed generation,
    /// predecessor, stage, evidence or digest.
    pub fn validate(&self) -> Result<(), AdmissionProgressErrorV1> {
        if self.plan_digest.as_bytes() == &[0; 32]
            || self.generation == 0
            || (self.generation == 1) != self.predecessor.is_none()
            || self.evidence.as_bytes() == &[0; 32]
            || (self.stage != AdmissionStageV1::Uncertain && self.stage != self.last_certain_stage)
            || (self.stage == AdmissionStageV1::Uncertain
                && !(2..=9).contains(&stage_rank(self.last_certain_stage)))
            || self.digest != admission_progress_digest(self)
        {
            return Err(AdmissionProgressErrorV1);
        }
        Ok(())
    }
}

/// Retains the exact low-water reclamation gate created by a reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatermarkRequirementV1 {
    /// Reservation that first crossed high water.
    pub reservation: CacheReservationId,
    /// Exact admission plan owning the reservation.
    pub plan_digest: ObjectDigest,
    /// Bytes that had to be reclaimed to reach low water.
    pub required_bytes: u64,
    /// Exact physically observed reclaimed bytes applied so far.
    pub credited_bytes: u64,
}

/// Reports an invalid immutable-publication progress shape or transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("cache admission progress is invalid")]
pub struct AdmissionProgressErrorV1;

fn admission_progress_digest(progress: &AdmissionProgressV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.admission-progress.v1\0");
    hasher.update(progress.plan_digest.as_bytes());
    hasher.update([progress.stage as u8, progress.last_certain_stage as u8]);
    hasher.update(progress.generation.to_be_bytes());
    hasher.update(
        progress
            .predecessor
            .map_or([0; 32], |digest| *digest.as_bytes()),
    );
    hasher.update(progress.evidence.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

const fn stage_rank(stage: AdmissionStageV1) -> u8 {
    match stage {
        AdmissionStageV1::Reserved => 1,
        AdmissionStageV1::PrivateDestinationCreated => 2,
        AdmissionStageV1::ContentTransferred => 3,
        AdmissionStageV1::ContentVerified => 4,
        AdmissionStageV1::WritersClosed => 5,
        AdmissionStageV1::SealEnabledAndVerified => 6,
        AdmissionStageV1::InodeSynced => 7,
        AdmissionStageV1::CanonicalNamePublished => 8,
        AdmissionStageV1::ParentSynced => 9,
        AdmissionStageV1::CatalogCommitted => 10,
        AdmissionStageV1::Uncertain => 11,
        AdmissionStageV1::Quarantined | AdmissionStageV1::Aborted => 12,
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncertainty_preserves_last_certain_stage_and_cannot_commit_catalog() {
        let reserved = AdmissionProgressV1::reserved(
            ObjectDigest::from_bytes([1; 32]), ObjectDigest::from_bytes([2; 32]),
        ).unwrap();
        assert_eq!(reserved.mark_uncertain(ObjectDigest::from_bytes([3; 32])), Err(AdmissionProgressErrorV1));

        let created = reserved.advance(
            AdmissionStageV1::PrivateDestinationCreated, ObjectDigest::from_bytes([4; 32]),
        ).unwrap();
        let uncertain = created.mark_uncertain(ObjectDigest::from_bytes([5; 32])).unwrap();

        assert_eq!(uncertain.last_certain_stage, created.stage);
        assert_eq!(uncertain.resolve_uncertainty(AdmissionStageV1::Reserved, ObjectDigest::from_bytes([6; 32])), Err(AdmissionProgressErrorV1));
        assert_eq!(uncertain.resolve_uncertainty(AdmissionStageV1::CatalogCommitted, ObjectDigest::from_bytes([6; 32])), Err(AdmissionProgressErrorV1));
        assert!(uncertain.resolve_uncertainty(AdmissionStageV1::Quarantined, ObjectDigest::from_bytes([6; 32])).is_ok());
    }

    #[test]
    fn progress_rejects_forged_digest_and_generation_overflow() {
        let mut progress = AdmissionProgressV1::reserved(
            ObjectDigest::from_bytes([1; 32]), ObjectDigest::from_bytes([2; 32]),
        ).unwrap();
        progress.digest = ObjectDigest::from_bytes([7; 32]);
        assert_eq!(progress.validate(), Err(AdmissionProgressErrorV1));

        progress.generation = u64::MAX;
        assert_eq!(progress.advance(AdmissionStageV1::PrivateDestinationCreated, ObjectDigest::from_bytes([8; 32])), Err(AdmissionProgressErrorV1));
    }
}
