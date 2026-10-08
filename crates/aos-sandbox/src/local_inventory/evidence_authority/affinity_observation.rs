//! Sealed authenticated-liveness observations consumed by placement.
//!
//! The owner retains the original assignment observation, worker commitment,
//! and protected liveness record after consuming a singular verifier grant.
//! Exact context, currentness, Guardian, and durable-row checks stay together;
//! the result remains non-authorizing scheduling evidence.

use aos_sandbox_core::{
    AssignmentEpoch, DesiredGeneration, IncarnationId, NodeId, ObjectDigest, SandboxId,
};

use super::VerifierEvidenceGrantV1;
use crate::local_inventory::assignment::{NodeAssignmentObservationV1, VerifiedGuardianStateV1};
use crate::local_inventory::journal::{
    JournalEffectStateV1, MultiNodeJournalDomainV1, ProtectedJournalRecordV1,
};
use crate::local_inventory::placement_input::InvalidPlacementInput;

/// Records the controller-observed node for one affinity dependency.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AffinityPlacementV1 {
    observation: NodeAssignmentObservationV1,
    worker_identity_digest: ObjectDigest,
    liveness_record: ProtectedJournalRecordV1,
}

impl AffinityPlacementV1 {
    /// Constructs one non-authorizing affinity observation inside the liveness verifier.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPlacementInput::AffinityNotLive`] unless the exact
    /// worker, assignment generation, armed Guardian, protected durability,
    /// carrier binding, and currentness all agree.
    pub(in crate::local_inventory) fn from_liveness_verifier(
        grant: VerifierEvidenceGrantV1<(
            NodeAssignmentObservationV1,
            ObjectDigest,
            ProtectedJournalRecordV1,
            u64,
        )>,
    ) -> Result<Self, InvalidPlacementInput> {
        let (
            (observation, worker_identity_digest, liveness_record, coordinator_unix_seconds),
            verifier_domain_digest,
            replay_fence,
            issuance_sequence,
            verifier_context,
        ) = grant.into_parts();
        let liveness_digest = affinity_liveness_digest(&observation, worker_identity_digest);
        let durable_affinity = liveness_record
            .record()
            .state_payload()
            .assignment_state()
            .and_then(|state| {
                state
                    .affinities()
                    .iter()
                    .find(|affinity| affinity.sandbox == observation.sandbox())
            });
        if worker_identity_digest.as_bytes() == &[0; 32]
            || verifier_domain_digest.as_bytes() == &[0; 32]
            || replay_fence.as_bytes() == &[0; 32]
            || issuance_sequence == 0
            || verifier_context.node() != observation.node()
            || verifier_context.lineage() != observation.lineage()
            || !verifier_context.is_current_at(coordinator_unix_seconds)
            || observation.phase() != aos_sandbox_core::state::AssignmentPhase::Active
            || !observation
                .context()
                .is_current_at(coordinator_unix_seconds)
            || observation.observed_at_unix_seconds() > coordinator_unix_seconds
            || !observation.authority().is_some_and(|authority| {
                authority.guardian_state() == VerifiedGuardianStateV1::Armed
                    && authority.is_current_at(coordinator_unix_seconds)
            })
            || liveness_record.record().domain() != MultiNodeJournalDomainV1::Assignment
            || liveness_record.record().payload_digest() != observation.assignment_digest()
            || liveness_record.record().effect_state() != JournalEffectStateV1::Committed
            || liveness_record.record().effect_digest() != liveness_digest
            || durable_affinity.is_none_or(|affinity| {
                affinity.node != observation.node()
                    || affinity.incarnation != observation.incarnation()
                    || affinity.epoch != observation.epoch()
                    || affinity.desired_generation != observation.desired_generation()
                    || affinity.assignment_digest != observation.assignment_digest()
                    || affinity.worker_identity_digest != worker_identity_digest
                    || affinity.liveness_record_digest != liveness_digest
                    || affinity.live_until_unix_seconds < coordinator_unix_seconds
            })
            || liveness_record.context().node() != observation.node()
            || liveness_record.context().lineage() != observation.lineage()
            || liveness_record.context().audience_digest()
                != observation.context().audience_digest()
            || !liveness_record
                .context()
                .is_current_at(coordinator_unix_seconds)
        {
            return Err(InvalidPlacementInput::AffinityNotLive);
        }
        Ok(Self {
            observation,
            worker_identity_digest,
            liveness_record,
        })
    }

    /// Returns the exact dependent sandbox.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.observation.sandbox()
    }

    /// Returns the currently live worker node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.observation.node()
    }

    /// Returns the exact live assignment incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> IncarnationId {
        self.observation.incarnation()
    }

    /// Returns the exact live desired generation.
    #[must_use]
    pub const fn desired_generation(&self) -> DesiredGeneration {
        self.observation.desired_generation()
    }

    /// Returns the exact live assignment fencing epoch.
    #[must_use]
    pub const fn epoch(&self) -> AssignmentEpoch {
        self.observation.epoch()
    }

    /// Returns the exact live assignment semantic commitment.
    #[must_use]
    pub const fn assignment_digest(&self) -> ObjectDigest {
        self.observation.assignment_digest()
    }

    /// Returns the independently authenticated worker identity commitment.
    #[must_use]
    pub const fn worker_identity_digest(&self) -> ObjectDigest {
        self.worker_identity_digest
    }

    /// Reports whether the exact assignment and protected liveness proof remain current.
    #[must_use]
    pub fn is_current_at(&self, coordinator_unix_seconds: u64) -> bool {
        self.observation
            .context()
            .is_current_at(coordinator_unix_seconds)
            && self.observation.observed_at_unix_seconds() <= coordinator_unix_seconds
            && self.observation.authority().is_some_and(|authority| {
                authority.guardian_state() == VerifiedGuardianStateV1::Armed
                    && authority.is_current_at(coordinator_unix_seconds)
            })
            && self
                .liveness_record
                .context()
                .is_current_at(coordinator_unix_seconds)
    }

    /// Returns the exact protected durability capability for this liveness fact.
    #[must_use]
    pub const fn liveness_record(&self) -> &ProtectedJournalRecordV1 {
        &self.liveness_record
    }
}

fn affinity_liveness_digest(
    observation: &NodeAssignmentObservationV1,
    worker_identity_digest: ObjectDigest,
) -> ObjectDigest {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"aos.affinity-live-worker.v1\0");
    hasher.update(observation.node().as_bytes());
    hasher.update(observation.lineage().digest().as_bytes());
    hasher.update(observation.sandbox().as_bytes());
    hasher.update(observation.incarnation().as_bytes());
    hasher.update(observation.epoch().get().to_be_bytes());
    hasher.update(observation.desired_generation().get().to_be_bytes());
    hasher.update(observation.assignment_digest().as_bytes());
    hasher.update(worker_identity_digest.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}
