//! Requires the actual private native permit for selected restored activation.
//!
//! The parser and field comparators are DATA. Only the boot-owned once attempt
//! supplies this dispatch exception. Existing coordinator authentication stays
//! unchanged for every ordinary dispatcher and unselected restoration route.

use super::*;
use crate::{
    protocol_snapshot::PreparedArchivedNativeProtocolMapping,
    reference_packet::{
        Native5Policy,
        service::{
            ack_emitter::{NativeAckBoot, OriginalRestorationActivationPermit},
            complete_restore::activation::{
                PacketRestorationActivationPhase, PacketRestorationActivationScope,
            },
        },
    },
};
use std::{cell::RefCell, rc::Rc};

/// Borrows the original released World inputs without supplying a permit.
///
/// The private Boot lender and Control independently authenticate their exact
/// original allocation, scope, cached terminal, complete evidence and physical
/// release. These borrowed fields confer no action, checkpoint or row rights.
pub(crate) struct ReleasedWorldControlInputsData<'a> {
    /// Borrows the actual assigned World activation original.
    pub(crate) original: &'a Envelope,
    /// Borrows its physically published cached terminal.
    pub(crate) terminal: &'a Envelope,
    /// Borrows the same Source-bound target and restoration scope.
    pub(crate) scope: &'a PacketRestorationActivationScope,
    /// Borrows the actual private Boot allocation retained by the lender.
    pub(crate) boot: &'a Rc<RefCell<NativeAckBoot>>,
    /// Borrows the same installed and authenticated native mapping allocation.
    pub(crate) mapping: &'a Rc<RefCell<PreparedArchivedNativeProtocolMapping>>,
    /// Borrows the original independent physical Hold and release association.
    pub(crate) hold: &'a Rc<PacketCompleteRestorePhysicalHold>,
    /// Borrows the same immutable selected native policy.
    pub(crate) policy: &'a Native5Policy,
}

/// Counts actual caller/callee view headers beside all earlier release controls.
pub(crate) const fn original_released_world_inputs_counter_scratch_data() -> usize {
    2 * std::mem::size_of::<ReleasedWorldControlInputsData<'static>>()
        + std::mem::size_of::<usize>()
}

impl PacketControl {
    pub(crate) fn dispatch_original_restoration_activation_with_preflight(
        &mut self,
        request: &Envelope,
        permit: &OriginalRestorationActivationPermit,
        prepare: &mut dyn FnMut(&PacketControlReply) -> Result<(), ProviderError>,
    ) -> Result<&PacketControlReply, ProviderError> {
        if self.capture_creator != std::process::id()
            || !self.immediate
            || request
                .request_id
                .0
                .as_ref()
                .is_none_or(|id| self.originals.contains_key(id))
            || !matches!(request.method, Method::Activate | Method::WorldActivate)
        {
            return Err(refused());
        }
        permit.authenticate_control_request(
            request,
            &self.selection,
            self.complete_restored_hold.as_ref().ok_or_else(refused)?,
        )?;
        // begin_dispatch is spent by the endpoint before borrowing its retained
        // original. The same immutable loan is used throughout this dispatch.
        self.dispatch_prepared_with_restoration_activation(
            request,
            &mut ReplyPreparation {
                callback: Some(prepare),
                attempted: false,
            },
            None,
            None,
            Some(permit),
        )
    }

    pub(crate) fn original_restoration_activation_coordinator_data<'a>(
        &'a self,
        original: &Envelope,
        phase: PacketRestorationActivationPhase,
        retained_manifest: &mut Option<ActivationManifest>,
    ) -> Result<Option<&'a [u8]>, ProviderError> {
        if self.capture_creator != std::process::id()
            || self.fenced
            || !self.immediate
            || self.complete_restored_hold.is_none()
            || retained_manifest.is_some()
        {
            return Err(refused());
        }
        if phase == PacketRestorationActivationPhase::Arm {
            if original.method != Method::Activate {
                return Err(refused());
            }
            return Ok(None);
        }
        if original.method != Method::WorldActivate {
            return Err(refused());
        }
        let reference = ContentRef::deserialize(
            original
                .body
                .get("activation_manifest")
                .ok_or_else(refused)?,
        )
        .map_err(ContractError::from)?;
        let bytes = self.content.get(&reference).ok_or_else(refused)?;
        // This bounded manifest ingress was admitted before Child, independently
        // of the artifact's untrusted phase row and the larger coordinator DOM.
        let manifest = canonical::decode(bytes, FRAME)?;
        *retained_manifest = Some(manifest);
        let manifest = retained_manifest.as_ref().ok_or_else(refused)?;
        let coordinator = self
            .content
            .get(&manifest.coordinator_state_ref)
            .ok_or_else(refused)?;
        Ok(Some(coordinator))
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original restored activation permit differs")
}

impl PacketControl {
    pub(crate) fn authenticate_original_restoration_activation_hold_data(
        &self,
        expected: &std::rc::Rc<PacketCompleteRestorePhysicalHold>,
    ) -> Result<(), ProviderError> {
        if self.capture_creator != std::process::id()
            || self.fenced
            || !self.immediate
            || self
                .complete_restored_hold
                .as_ref()
                .is_none_or(|actual| !std::rc::Rc::ptr_eq(actual, expected))
            || !self.original_physical_gate_held()?
        {
            return Err(refused());
        }
        Ok(())
    }
}

impl PacketControl {
    pub(crate) fn install_original_complete_model_with_activation_requirement(
        &mut self,
        capsule: &mut PacketPreparedCompleteModel,
        requirement: crate::reference_packet::service::ack_emitter::OriginalRestorationActivationRequirement,
    ) -> Result<std::rc::Rc<PacketCompleteRestorePhysicalHold>, ProviderError> {
        let required = requirement.authenticate_model_data(capsule, &self.selection)?;
        // Set the actual boot's policy before the first model/socket move. A
        // failed selected installation cannot reopen the generic dispatch seam.
        self.restoration_activation_required = required;
        self.install_original_complete_model(capsule)
    }
}

impl PacketControl {
    /// Retains one new inert signed-upload object under the unchanged ledger.
    ///
    /// # Errors
    /// Refuses a foreign lifecycle, content-ID reuse or existing object/total
    /// capacity refusal. Only the boot-owned upload dispatcher calls this seam.
    pub(crate) fn install_original_restoration_upload_content_data(
        &mut self,
        content: ContentRef,
        bytes: &[u8],
    ) -> Result<(), ProviderError> {
        if self.capture_creator != std::process::id()
            || self.fenced
            || !self.immediate
            || !self.restoration_activation_required
            || self.complete_restored_hold.is_none()
            || self.content.contains_key(&content)
        {
            return Err(refused());
        }
        self.install_content(content, bytes)
    }
}

impl PacketControl {
    /// Authenticates only the actual cached World publication and physical release.
    ///
    /// This borrowed DATA check issues no execution/input/resource/Capture right.
    /// The caller separately proves its same connection's physically sent prefix.
    ///
    /// # Errors
    /// Refuses changed real owner, cached terminal, active World, proof/content
    /// banks, selection or the independent physical release association.
    pub(crate) fn authenticate_original_restoration_released_control_data(
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
            reference.verify(bytes)?;
            if self.content.get(reference) != Some(bytes) {
                return Err(refused());
            }
        }
        Ok(())
    }
}

impl PacketControl {
    pub(crate) fn dispatch_original_restoration_observation_with_preflight(
        &mut self,
        request: &Envelope,
        permit: &crate::reference_packet::service::ack_emitter::OriginalRestorationObservationPermit,
        prepare: &mut dyn FnMut(&PacketControlReply) -> Result<(), ProviderError>,
    ) -> Result<&PacketControlReply, ProviderError> {
        if request.method != Method::Observe
            || !self.immediate
            || self.fenced
            || request
                .request_id
                .0
                .as_ref()
                .is_none_or(|id| self.originals.contains_key(id))
        {
            return Err(refused());
        }
        permit.authenticate_control_request_data(request, &self.selection, self)?;
        self.dispatch_prepared_with_restoration_permissions(
            request,
            &mut ReplyPreparation {
                callback: Some(prepare),
                attempted: false,
            },
            None,
            None,
            None,
            Some(permit),
            None,
            None,
        )
    }

    // This checks the actual cached producer result, not a reconstructed DTO or
    // receipt label. The Source independently authenticates the full proof pair.
    pub(crate) fn authenticate_original_restoration_observation_terminal_data(
        &self,
        original: &Envelope,
        terminal: &Envelope,
    ) -> Result<(), ProviderError> {
        if self.capture_creator != std::process::id()
            || self.fenced
            || !self.immediate
            || original.method != Method::Observe
            || self.original_physical_gate_held()?
        {
            return Err(refused());
        }
        let cached = &self
            .originals
            .get(original.request_id.0.as_ref().ok_or_else(refused)?)
            .ok_or_else(refused)?
            .1;
        if cached.body != terminal.body
            || terminal.body.get("status").and_then(Value::as_str) != Some("completed")
            || terminal.body.get("operation_state").and_then(Value::as_str) != Some("completed")
        {
            return Err(refused());
        }
        let result = terminal
            .body
            .get("result")
            .and_then(Value::as_object)
            .ok_or_else(refused)?;
        let observations = result
            .get("observations")
            .and_then(Value::as_array)
            .ok_or_else(refused)?;
        let [batch] = observations.as_slice() else {
            return Err(refused());
        };
        if result.get("complete").and_then(Value::as_bool) != Some(true)
            || result.get("next_sequence").and_then(Value::as_str) != Some("1")
            || batch
                .get("events")
                .and_then(Value::as_array)
                .is_none_or(|events| !events.is_empty())
        {
            return Err(refused());
        }
        for (reference, bytes) in &cached.evidence {
            reference.verify(bytes)?;
            if self.content.get(reference) != Some(bytes) {
                return Err(refused());
            }
        }
        Ok(())
    }
}

/// Names the exact borrowed release/Observe cached-result and content views.
pub(crate) fn original_restoration_released_counter_scratch_data() -> usize {
    use std::mem::size_of;
    // The incoming step retains its original service-context headers while the
    // separately admitted release or observation validates this same owner.
    crate::reference_packet::endpoint::original_endpoint_context_counter_scratch_data()
        + original_released_world_inputs_counter_scratch_data()
        + size_of::<&WorldActivateRequest>()
        + size_of::<&PacketControlReply>()
        + size_of::<Option<&PacketControlReply>>()
        + size_of::<Option<&Value>>() * 4
        + size_of::<Result<&Value, ProviderError>>()
        + size_of::<Option<&Map<String, Value>>>()
        + size_of::<Result<&Map<String, Value>, ProviderError>>()
        + size_of::<Option<&Vec<Value>>>()
        + size_of::<Result<&Vec<Value>, ProviderError>>()
        + size_of::<Option<&(HashRef, PacketControlReply)>>()
        + size_of::<Option<&(ContentRef, Vec<u8>)>>()
        + size_of::<std::slice::Iter<'static, (ContentRef, Vec<u8>)>>()
        + size_of::<(&'static ContentRef, &'static Vec<u8>)>()
        + size_of::<&[Value]>()
        + size_of::<Result<(), ProviderError>>()
}
