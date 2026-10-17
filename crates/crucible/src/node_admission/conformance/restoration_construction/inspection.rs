//! Borrows a completed original transaction without renewing an effect phase.
//!
//! The genuine retained window alone constructs this view. It is not a Claim,
//! receipt, final context or conversion to one. Source independently verifies
//! its same private attempt, full SDK originals, keyed receipts and SourceRead.

use super::*;

pub(crate) struct OriginalRestorationTransactionInspection<'a> {
    pub(super) window: &'a CompleteOriginalRestorationWindow,
    pub(super) target: &'a CompleteOriginalRestorationTransactionTarget,
    pub(super) source: &'a Rc<PacketCompleteSemanticSource>,
    pub(super) plan: &'a InstalledConformancePlan,
    pub(super) activation: &'a ActivationRecord,
    pub(super) installed_scope: Option<&'a crate::node_contract::OriginalLineageNativeScope>,
}

impl OriginalRestorationTransactionInspection<'_> {
    /// Rechecks the real retained member and terminal live runtime identity.
    pub(crate) fn authenticate_current(&self) -> Result<(), RuntimeError> {
        if let Some(scope) = self.installed_scope {
            return self
                .window
                .authenticate_original_complete_identity_data(self.plan, scope);
        }
        self.window.authenticate_original_completed_member_data(
            self.target,
            self.source,
            self.plan,
            self.activation,
        )?;
        self.window
            .authenticate_original_runtime_member_current_data(&self.activation.world_binding_hash)
    }

    /// Borrows the same immutable signed originals after the completed-member gate.
    pub(crate) fn original_inputs_data(
        &self,
    ) -> Result<OriginalRestorationSigningInputs<'_>, RuntimeError> {
        self.authenticate_current()?;
        self.window.original_signing_inputs_data(
            self.target,
            self.source,
            self.plan,
            self.activation,
        )
    }
}
