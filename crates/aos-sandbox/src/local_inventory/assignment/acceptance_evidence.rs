//! Optional authenticated node-acceptance evidence.
//!
//! The sealed acceptance owner retains its consumed verifier grant and complete
//! intent, observation, capability, lease, Guardian, and protected-journal joins.
//! Local assignment DATA and retained-history validation remain in the parent.

use sha2::{Digest as _, Sha256};

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_core::state::AssignmentPhase;

use crate::local_inventory::capability::CarrierValidatedCapabilityObservationV1;
use crate::local_inventory::evidence_authority::VerifierEvidenceGrantV1;
use crate::local_inventory::journal::{
    JournalEffectStateV1, MultiNodeJournalDomainV1, ProtectedJournalRecordV1,
};

use super::{
    AssignmentIntentV1, InvalidAssignmentModel, NodeAssignmentObservationV1,
    VerifiedAssignmentAuthorityV1,
};

/// Proves exact node acceptance with current lease and armed Guardian evidence.
///
/// Construction is restricted to the verifier boundary and does not transfer
/// the separately issued ownership authority it observes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAssignmentAcceptanceV1 {
    intent: AssignmentIntentV1,
    observation: NodeAssignmentObservationV1,
    capability_observation: CarrierValidatedCapabilityObservationV1,
    capability_evidence_digest: ObjectDigest,
    lease_generation: u64,
    lease_digest: ObjectDigest,
    guardian_digest: ObjectDigest,
    journal_record: ProtectedJournalRecordV1,
}

impl VerifiedAssignmentAcceptanceV1 {
    /// Constructs exact acceptance from current authenticated node evidence.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAssignmentModel::AuthorityMismatch`] unless tuple,
    /// lifecycle, phase, boot, lease, Guardian, carrier, and currentness match.
    pub(in crate::local_inventory) fn from_owner_verifier(
        grant: VerifierEvidenceGrantV1<(
            AssignmentIntentV1,
            NodeAssignmentObservationV1,
            CarrierValidatedCapabilityObservationV1,
            ProtectedJournalRecordV1,
            u64,
        )>,
    ) -> Result<Self, InvalidAssignmentModel> {
        let (
            (intent, observation, capability_observation, journal_record, coordinator_unix_seconds),
            verifier_domain_digest,
            replay_fence,
            issuance_sequence,
            verifier_context,
        ) = grant.into_parts();
        let authority = observation
            .authority()
            .ok_or(InvalidAssignmentModel::AuthorityMismatch)?;
        let capability_evidence_digest = capability_observation.evidence_binding_digest();
        let acceptance_effect_digest = assignment_acceptance_effect_digest(&intent, authority);
        if verifier_domain_digest.as_bytes() == &[0; 32]
            || replay_fence.as_bytes() == &[0; 32]
            || replay_fence != verifier_context.replay_fence()
            || issuance_sequence == 0
            || verifier_context != observation.context()
            || !observation.matches(&intent)
            || observation.phase() != AssignmentPhase::Active
            || observation.realized_lifecycle() != Some(intent.desired_lifecycle())
            || !observation
                .context()
                .is_current_at(coordinator_unix_seconds)
            || !intent
                .selected_capability_binding()
                .matches_current(&capability_observation, coordinator_unix_seconds)
            || capability_observation.audience_node() != intent.node()
            || capability_observation.snapshot().lineage() != observation.lineage()
            || capability_observation.coordinator_epoch()
                != observation.context().coordinator_epoch()
            || capability_observation.audience_digest() != observation.context().audience_digest()
            || capability_observation.disclosure_domain_digest()
                != observation.context().disclosure_domain_digest()
            || capability_observation.carrier_binding_digest()
                != observation.context().carrier_binding_digest()
            || capability_observation.replay_fence() != observation.context().replay_fence()
            || authority.context() != observation.context()
            || !authority.is_current_for(&intent, observation.lineage(), coordinator_unix_seconds)
            || journal_record.record().domain() != MultiNodeJournalDomainV1::Assignment
            || journal_record.record().payload_digest() != intent.assignment_digest()
            || journal_record.record().state_payload().assignment_digest()
                != Some(intent.assignment_digest())
            || journal_record
                .record()
                .state_payload()
                .assignment_capability_evidence_digest()
                != Some(capability_evidence_digest)
            || journal_record.record().effect_state() != JournalEffectStateV1::Committed
            || journal_record.record().effect_digest() != acceptance_effect_digest
            || !journal_record
                .context()
                .is_current_at(coordinator_unix_seconds)
            || journal_record.context() != observation.context()
        {
            return Err(InvalidAssignmentModel::AuthorityMismatch);
        }
        Ok(Self {
            intent,
            observation,
            capability_observation,
            capability_evidence_digest,
            lease_generation: authority.lease_generation(),
            lease_digest: authority.lease_digest(),
            guardian_digest: authority.guardian_digest(),
            journal_record,
        })
    }

    /// Returns the exact accepted assignment intent.
    #[must_use]
    pub const fn intent(&self) -> &AssignmentIntentV1 {
        &self.intent
    }

    /// Returns the authenticated active node observation.
    #[must_use]
    pub const fn observation(&self) -> &NodeAssignmentObservationV1 {
        &self.observation
    }

    /// Returns the live capability observation revalidated at acceptance.
    #[must_use]
    pub const fn capability_observation(&self) -> &CarrierValidatedCapabilityObservationV1 {
        &self.capability_observation
    }

    /// Returns the exact selected capability identity/currentness commitment.
    #[must_use]
    pub const fn capability_evidence_digest(&self) -> ObjectDigest {
        self.capability_evidence_digest
    }

    /// Returns the verified lease generation.
    #[must_use]
    pub const fn lease_generation(&self) -> u64 {
        self.lease_generation
    }

    /// Returns the lease commitment without carrying authority bytes.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns the exact armed Guardian observation commitment.
    #[must_use]
    pub const fn guardian_digest(&self) -> ObjectDigest {
        self.guardian_digest
    }

    /// Returns the durable exact-acceptance journal record.
    #[must_use]
    pub const fn journal_record(&self) -> &ProtectedJournalRecordV1 {
        &self.journal_record
    }

    /// Reports whether the exact lease, Guardian, carrier, and durability evidence is current.
    #[must_use]
    pub fn is_current_at(&self, coordinator_unix_seconds: u64) -> bool {
        self.observation
            .context()
            .is_current_at(coordinator_unix_seconds)
            && self
                .capability_observation
                .is_current_at(coordinator_unix_seconds)
            && self.capability_evidence_digest
                == self.capability_observation.evidence_binding_digest()
            && self
                .intent
                .selected_capability_binding()
                .matches_current(&self.capability_observation, coordinator_unix_seconds)
            && self.observation.observed_at_unix_seconds() <= coordinator_unix_seconds
            && self.observation.authority().is_some_and(|authority| {
                authority.is_current_for(
                    &self.intent,
                    self.observation.lineage(),
                    coordinator_unix_seconds,
                )
            })
            && self
                .journal_record
                .context()
                .is_current_at(coordinator_unix_seconds)
    }
}

fn assignment_acceptance_effect_digest(
    intent: &AssignmentIntentV1,
    authority: VerifiedAssignmentAuthorityV1,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.assignment.acceptance-effect.v1\0");
    hasher.update(intent.sandbox().as_bytes());
    hasher.update(intent.incarnation().as_bytes());
    hasher.update(intent.node().as_bytes());
    hasher.update(intent.epoch().get().to_be_bytes());
    hasher.update(intent.desired_generation().get().to_be_bytes());
    hasher.update(intent.assignment_digest().as_bytes());
    hasher.update(
        intent
            .selected_capability_binding()
            .evidence_binding_digest()
            .as_bytes(),
    );
    hasher.update(authority.lease_generation().to_be_bytes());
    hasher.update(authority.lease_digest().as_bytes());
    hasher.update(authority.guardian_digest().as_bytes());
    hasher.update(authority.audience_digest().as_bytes());
    hasher.update(authority.carrier_frame_digest().as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}
