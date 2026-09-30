//! Checks the complete pending Start ledger before current-owner acquisition.
//!
//! Original carrier data is read through the existing admission decoder. The
//! extra checks restrict continuation to its exact pending step and Desired
//! bytes; they never settle an Effect or construct authorization evidence.

use super::*;

impl NixStartAdmissionCarrierV2 {
    pub(crate) fn require_current_effect_v2(
        &self,
        journal: &Journal,
        operation_id: OperationId,
        step: u32,
        expected_plan: &EffectPlan,
    ) -> Result<(), ReconcilerError> {
        journal.validate_held_protected_names()?;
        if step != 0 || self.operation() != operation_id {
            return Err(ReconcilerError::CorruptLedger("unexpected retained Start step"));
        }
        let readback = accepted_nix_start_readback_v2(journal, operation_id)?
            .ok_or(ReconcilerError::CorruptLedger("missing retained Start admission"))?;
        let original = readback.context.nix_start()
            .ok_or(ReconcilerError::CorruptLedger("missing retained Start admission"))?;
        if original != self {
            return Err(ReconcilerError::CorruptLedger("retained Start original changed"));
        }

        // Later custody cuts read afresh; reuse is confined to this immutable phase.
        require_pending_states(readback.operation.state, &readback.effect.state)?;
        let (desired_key, desired_value) = self.desired();
        if &readback.effect.plan != expected_plan
            || readback.effect.dispatch.is_some()
            || readback.effect.project_admission.is_some()
            || journal.get(RecordNamespace::DesiredState, desired_key) != Some(desired_value)
        {
            return Err(ReconcilerError::CorruptLedger("retained Start effect or Desired changed"));
        }
        journal.validate_held_protected_names()?;
        Ok(())
    }
}

fn require_pending_states(
    operation: OperationState,
    effect: &EffectState,
) -> Result<(), ReconcilerError> {
    // This retained operation has exactly one Effect. Preserve the existing
    // public-operation state matrix rather than accepting contradictory pairs.
    if !matches!((operation, effect),
        (OperationState::Accepted, EffectState::Planned)
            | (OperationState::Applying, EffectState::Applying { .. }))
    {
        return Err(ReconcilerError::CorruptLedger("retained Start is not pending"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_pending_operation_and_effect_pairs_continue() {
        let applying = EffectState::Applying { attempt: 1, diagnostic: String::new() };

        assert!(require_pending_states(OperationState::Accepted, &EffectState::Planned).is_ok());
        assert!(require_pending_states(OperationState::Applying, &applying).is_ok());
        assert!(require_pending_states(OperationState::Accepted, &applying).is_err());
        assert!(require_pending_states(OperationState::Applying, &EffectState::Planned).is_err());

        for operation in [OperationState::Succeeded, OperationState::PermanentlyBlocked,
            OperationState::OwnershipPending, OperationState::CanceledBeforeCommit,
            OperationState::FailedBeforeCommit]
        {
            assert!(require_pending_states(operation, &EffectState::Planned).is_err());
        }
    }

    #[test]
    fn completed_or_blocked_effect_cannot_continue() {
        let applied = EffectState::Applied {
            attempt: 1, receipt: EffectReceipt(vec![1]),
        };
        let blocked = EffectState::PermanentlyBlocked {
            attempt: 1, diagnostic: String::new(),
        };

        for operation in [OperationState::Accepted, OperationState::Applying] {
            assert!(require_pending_states(operation, &applied).is_err());
            assert!(require_pending_states(operation, &blocked).is_err());
        }
    }
}
