//! Dispatches selected Capture17 through the actual installed Node and Source.
//!
//! The synchronous ticket lends the real current collecting scope and launch
//! operands. The original association supplies the same Window; its distinct
//! claim and Source's retained armed read remain separate prerequisites. The
//! ordinary ticket path keeps its existing unsupported/default behavior.

use crate::node_adapters::cnp::semantic::{CnpSemanticNode, CnpSemanticSource, refused, unknown};
use crate::{
    node_admission::CompleteOriginalRestorationWindow,
    node_contract::{
        EffectKnowledge, InstalledOriginalLineageCapture, NativeCaptureLimits, OperationFailure,
        OriginalLineageOwnerCaptureTicket, OriginalLineageRuntimeRecord,
        RestoredCollectingCaptureScope17, RuntimeError, WorldActivation,
    },
    node_scheduling::InputPayload,
};
use std::rc::Rc;

impl CnpSemanticNode {
    /// Runs the selected producer while retaining every original callback loan.
    ///
    /// The complete result slot is filled before final checks. On refusal it
    /// stays with the actual Core attempt, while Source/SDK partials stay with
    /// their original holders. Dropping the real claim dirties whole ownership;
    /// the enclosing writer must release all loans and perform its full census
    /// before entering another owner, rather than calling ordinary currentness
    /// after that drop.
    pub(in crate::node_adapters::cnp::semantic) fn capture_with_restored17_ticket_into(
        &mut self,
        erased: &dyn CnpSemanticSource,
        scope: &RestoredCollectingCaptureScope17<'_>,
        ticket: &OriginalLineageOwnerCaptureTicket<'_>,
        activation: &WorldActivation,
        record: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        limits: NativeCaptureLimits,
        completed: &mut Option<InstalledOriginalLineageCapture>,
    ) -> Result<(), OperationFailure> {
        self.preparation.guard.custody().map_err(unknown)?;
        if completed.is_some()
            || !scope.world_data().same_authority(activation)
            || scope.capture_id_data() != ticket.capture_id()
        {
            return Err(refused("Capture17 scope or destination differs"));
        }
        scope.authenticate_current_data().map_err(unknown)?;
        let (window, selected) = self
            .original_capture17_window_data(erased)
            .map_err(unknown)?;
        let source = window
            .original_restored_capture_source_data(selected, erased)
            .map_err(unknown)?;
        if !source
            .requires_restored_capture17_scope_data()
            .map_err(unknown)?
        {
            return Err(refused(
                "current ticket belongs to a Source without Capture17 selection",
            ));
        }
        let (launch, raw5) = scope.original_source_launch_data(source).map_err(unknown)?;
        let route = &self.route;
        let owner = route
            .owners
            .first()
            .filter(|_| route.owners.len() == 1)
            .ok_or_else(|| refused("Capture17 owner route differs"))?;
        let supervisor = self
            .retained_supervisor
            .as_ref()
            .ok_or_else(|| refused("Capture17 retained supervisor is absent"))?;
        let native = self
            .preparation
            .guard
            .custody
            .as_mut()
            .ok_or_else(|| refused("Capture17 native custody is absent"))?;
        native.authenticate_process().map_err(unknown)?;

        let result = source.with_original_retained_capture17_read_data(|read| {
            // This is the existing Source association's real read. No new read
            // handle, registrar, process capsule or borrowed supervisor is minted.
            if !read.same_native_owner(native) {
                return Err(RuntimeError::ForeignAuthority);
            }
            let read_owner = Rc::as_ptr(&native.read_owner).cast();
            let controller = native
                .controller
                .as_mut()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let base = native
                .runtime
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let world = base.active.as_ref().ok_or(RuntimeError::NotActivated)?;
            if !world.same_authority(activation) {
                return Err(RuntimeError::ForeignAuthority);
            }
            let claim = window.begin_restored_capture_owner_claim_data(
                selected,
                source,
                controller,
                read_owner,
                world,
                ticket,
                record,
                runtime_object,
            )?;
            claim
                .row_data()
                .authenticate_capture_output_limits_data(limits)?;
            // The Runtime row independently paid exactly two full ticket
            // validations for this Source. Fast row/identity checks inside the
            // transport do not substitute for either complete Runtime7 join.
            claim.authenticate_ticket_data(owner, ticket.participants())?;
            let mut scratch = read.original_fresh_current_scratch()?;
            let call = read.begin_original_fresh_query_call_data(&mut scratch)?;
            let node = super::capture_history::view_for_current_capture_scope_data(
                base, route, controller, supervisor, &claim,
            )?;
            claim.with_original_inputs_data(source, |inputs| {
                window.with_restored_capture_encoding_inputs_data(
                    &claim,
                    source,
                    controller,
                    inputs,
                    |encoding| {
                        source.run_original_restored_capture_source_data(
                            controller,
                            launch,
                            raw5,
                            inputs,
                            &claim,
                            &node,
                            encoding,
                            call,
                            &mut scratch,
                            |completion| {
                                completion.materialize_installed_capture_into_data(
                                    source, &claim, limits, completed,
                                )
                            },
                        )
                    },
                )
            })?;
            claim.authenticate_ticket_data(owner, ticket.participants())?;
            read.ensure_original_fresh_current(&mut scratch)?;
            scope.authenticate_current_data()?;
            // Claim Drop runs after all final guards and before returning to the
            // genuine whole-owner observer in the enclosing archive writer.
            Ok(())
        });
        // The Source path is selected and may already have dispatched native
        // work. Preserve any completed Core output before recording uncertainty.
        if let Err(error) = result {
            let failure = unknown(error);
            if failure.effects == EffectKnowledge::Unknown {
                self.state_mut()?.quarantined = true;
            }
            return Err(failure);
        }
        Ok(())
    }

    fn original_capture17_window_data(
        &self,
        erased: &dyn CnpSemanticSource,
    ) -> Result<(Rc<CompleteOriginalRestorationWindow>, usize), RuntimeError> {
        let installed = self
            .preparation
            .guard
            .custody
            .as_ref()
            .and_then(|native| native.runtime.as_ref())
            .and_then(|runtime| runtime.installed_restoration.as_ref())
            .ok_or(RuntimeError::UnsupportedFacet)?;
        installed.association.original_capture17_window_data(erased)
    }
}

/// Names the selected Node dispatcher and its actual synchronous loans.
///
/// The Source and Runtime rows independently pay their defining serializers,
/// native scratch banks and two complete ticket-validation windows.
pub(super) fn counter_scratch_data() -> usize {
    use crate::node_adapters::cnp::{CnpSemanticSourceRead, PacketCompleteSemanticSource};
    use crate::node_admission::OriginalRestoredCaptureClaim;
    use crucible_node_transport::{client::CnpController, connection::OriginalRetainedSupervisor};
    use std::mem::size_of;

    PacketCompleteSemanticSource::original_retained_capture17_read_counter_scratch_data::<()>()
        + PacketCompleteSemanticSource::original_restored_capture_scope_selection_counter_scratch_data()
        + size_of::<&CnpSemanticNode>()
        + size_of::<&mut CnpSemanticNode>()
        + size_of::<&dyn CnpSemanticSource>()
        + size_of::<&PacketCompleteSemanticSource>()
        + size_of::<Rc<CompleteOriginalRestorationWindow>>()
        + size_of::<Result<(Rc<CompleteOriginalRestorationWindow>, usize), RuntimeError>>()
        + size_of::<&RestoredCollectingCaptureScope17<'static>>()
        + size_of::<&OriginalLineageOwnerCaptureTicket<'static>>()
        + size_of::<&WorldActivation>()
        + size_of::<&OriginalLineageRuntimeRecord>()
        + size_of::<&InputPayload>()
        + size_of::<NativeCaptureLimits>()
        + size_of::<&mut Option<InstalledOriginalLineageCapture>>()
        + size_of::<&CnpSemanticSourceRead>()
        + size_of::<&OriginalRetainedSupervisor>()
        + size_of::<&mut CnpController>()
        + size_of::<&crate::node_contract::NodeRoute>()
        + size_of::<&crate::node_contract::OwnerIdentity>()
        + size_of::<*const ()>()
        + size_of::<OriginalRestoredCaptureClaim<'static>>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<Result<(), OperationFailure>>()
        + size_of::<Result<bool, RuntimeError>>()
}
