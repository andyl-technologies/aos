//! Rechecks the immutable released World custody beneath the actual17 lender.
//!
//! The live Boot lender already requires the real verified/published World and
//! first-observation owners. This borrowed check preserves those exact Control,
//! hold, mapping, policy, active World and cached output associations without
//! allocating another canonical/hash bank. It confers no current-model, action
//! or row permission. The funded checkpoint comparer independently rehashes its
//! exact proof pair before any producer effect. Old public validators are intact.

use super::*;
use crate::reference_packet::control::ReleasedWorldControlInputsData;

impl PacketControl {
    /// Rejoins the same physically released World and immutable cached output.
    ///
    /// # Errors
    /// Refuses foreign/fenced Control, changed private released custody, policy,
    /// active World/hold or cached terminal/content correspondence.
    pub(crate) fn authenticate_observation17_world_cache_data(
        &self,
        inputs: ReleasedWorldControlInputsData<'_>,
    ) -> Result<(), ProviderError> {
        let ReleasedWorldControlInputsData {
            original,
            terminal,
            scope,
            boot,
            mapping,
            hold,
            policy,
        } = inputs;

        original.matches_response(terminal)?;
        if self.capture_creator != std::process::id()
            || self.fenced
            || !self.immediate
            || !self.restoration_activation_required
            || original.method != Method::WorldActivate
            || terminal.method != original.method
            || terminal.request_id != original.request_id
            || terminal.session_id != original.session_id
            || terminal.incarnation_id != original.incarnation_id
            || self
                .complete_restored_hold
                .as_ref()
                .is_none_or(|actual| !std::rc::Rc::ptr_eq(actual, hold))
            || self.original_physical_gate_held()?
            || hold.physical_gate_data()?
        {
            return Err(refused());
        }
        policy.authenticate_original_control_selection(&self.selection)?;
        self.complete_restored_evidence
            .as_ref()
            .ok_or_else(refused)?
            .authenticate_released_custody_data(boot, mapping, hold)?;
        let active = self.active.as_ref().ok_or_else(refused)?;
        if active.transaction_id != scope.target.transaction
            || active.activation_id != scope.target.activation
            || active.world_generation != scope.target.generation
            || active.gate_id != scope.target.gate
            || active.prepared_token != scope.target.prepared_token
            || active.world_binding_hash != scope.target.world
            || original
                .body
                .get("activation_manifest")
                .is_none_or(|value| {
                    !super::fresh_report::borrowed_reference_matches(
                        value,
                        &active.activation_manifest,
                    )
                })
        {
            return Err(refused());
        }
        let request_id = original.request_id.0.as_ref().ok_or_else(refused)?;
        let cached = &self.originals.get(request_id).ok_or_else(refused)?.1;
        if cached.body != terminal.body {
            return Err(refused());
        }
        let (receipt, _) = cached.evidence.last().ok_or_else(refused)?;
        let actual_receipt = cached
            .body
            .get("result")
            .and_then(Value::as_object)
            .and_then(|result| result.get("activation_receipt"))
            .ok_or_else(refused)?;
        if !super::fresh_report::borrowed_reference_matches(actual_receipt, receipt) {
            return Err(refused());
        }
        for (reference, bytes) in &cached.evidence {
            if self.content.get(reference) != Some(bytes) {
                return Err(refused());
            }
        }
        Ok(())
    }
}
