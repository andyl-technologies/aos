//! Requires the actual private native permit for selected restored activation.
//!
//! The parser and field comparators are DATA. Only the boot-owned once attempt
//! supplies this dispatch exception. Existing coordinator authentication stays
//! unchanged for every ordinary dispatcher and unselected restoration route.

use super::*;
use crate::reference_packet::service::{
    ack_emitter::OriginalRestorationActivationPermit,
    complete_restore::activation::PacketRestorationActivationPhase,
};

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
