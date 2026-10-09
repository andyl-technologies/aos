use aos_sandbox_core::{ObjectDigest, OperationId};

use crate::local_inventory::assignment::{AssignmentEffectPlanV1, AssignmentIntentV1};

use super::{
    InvalidMultiNodeJournal, JournalEffectStateV1, MultiNodeJournalDomainV1,
    MultiNodeJournalReducerV1,
};

impl MultiNodeJournalReducerV1 {
    /// Issues a sealed semantic grant for the current prepared assignment effect.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::InvalidRecoveryTransition`] unless the
    /// exact current row is protected, assignment-bound, and commits a prepared
    /// operation and effect.
    pub(in crate::local_inventory) fn issue_assignment_effect_grant(
        &self,
        plan: AssignmentEffectPlanV1,
    ) -> Result<AssignmentEffectSemanticGrantV1, InvalidMultiNodeJournal> {
        let record = self
            .current
            .as_ref()
            .ok_or(InvalidMultiNodeJournal::InvalidRecoveryTransition)?;
        let receipt_commitment = self
            .current_receipt_commitment
            .ok_or(InvalidMultiNodeJournal::InvalidRecoveryTransition)?;
        let authority_binding_digest = self
            .current_authority_binding_digest
            .ok_or(InvalidMultiNodeJournal::InvalidRecoveryTransition)?;
        let assignment = record
            .state_payload()
            .assignment_state()
            .ok_or(InvalidMultiNodeJournal::InvalidRecoveryTransition)?;
        let intent = assignment.intent();
        if self.domain != MultiNodeJournalDomainV1::Assignment
            || record.domain() != MultiNodeJournalDomainV1::Assignment
            || record.effect_state() != JournalEffectStateV1::EffectPrepared
            || record.payload_digest() != intent.assignment_digest()
            || !plan.matches(record.operation(), intent, record.effect_digest())
        {
            return Err(InvalidMultiNodeJournal::InvalidRecoveryTransition);
        }
        Ok(AssignmentEffectSemanticGrantV1 {
            plan,
            record_digest: record.digest(),
            receipt_commitment,
            authority_binding_digest,
        })
    }
}

/// Carries one reducer-issued prepared-assignment semantic commitment.
///
/// Construction remains private to [`MultiNodeJournalReducerV1`]. The move-only
/// grant prevents an effect from being authorized solely from caller-provided
/// operation or digest scalars.
#[must_use]
pub(in crate::local_inventory) struct AssignmentEffectSemanticGrantV1 {
    plan: AssignmentEffectPlanV1,
    record_digest: ObjectDigest,
    receipt_commitment: ObjectDigest,
    authority_binding_digest: ObjectDigest,
}

impl AssignmentEffectSemanticGrantV1 {
    pub(in crate::local_inventory) const fn operation(&self) -> OperationId {
        self.plan.operation()
    }

    pub(in crate::local_inventory) const fn payload_digest(&self) -> ObjectDigest {
        self.plan.intent().assignment_digest()
    }

    pub(in crate::local_inventory) const fn effect_digest(&self) -> ObjectDigest {
        self.plan.effect_digest()
    }

    pub(in crate::local_inventory) const fn intent(&self) -> &AssignmentIntentV1 {
        self.plan.intent()
    }

    pub(in crate::local_inventory) fn matches(
        &self,
        operation: OperationId,
        intent: &AssignmentIntentV1,
        effect_digest: ObjectDigest,
    ) -> bool {
        self.plan.matches(operation, intent, effect_digest)
    }

    pub(in crate::local_inventory) const fn record_digest(&self) -> ObjectDigest {
        self.record_digest
    }

    pub(in crate::local_inventory) const fn receipt_commitment(&self) -> ObjectDigest {
        self.receipt_commitment
    }

    pub(in crate::local_inventory) const fn authority_binding_digest(&self) -> ObjectDigest {
        self.authority_binding_digest
    }
}
