//! Owns ticketed capture loans over the same original CNP process capsule.
//!
//! This forwarding route does not install a preservation mechanism. Legacy
//! sources retain CaptureNone, and the source callback refuses by default.
//! A selected native mechanism must independently authenticate its complete
//! snapshot and original administrative request/response settlement.

use std::rc::Rc;

use crucible_node_transport::bodies::{
    BeginArguments, BeginRequest, DiscoverResult, RealizeResult, ResponseBody,
};

use crate::{
    node_contract::{
        InstalledOriginalLineageCapture, NativeCaptureLimits, OperationFailure,
        OriginalLineageOwnerCaptureTicket, OriginalLineageRuntimeRecord, OwnerIdentity,
        WorldActivation,
    },
    node_scheduling::InputPayload,
};

use super::{
    CnpSemanticInstallation, CnpSemanticNode, CnpSemanticProcessCustody,
    CnpSemanticRealizationScope, CnpSemanticSource, process::ReadCall, refused, unknown,
};

/// Lends the same original native capsule to an installed administrative capture.
///
/// The loan retains Rust-exclusive controller access without replacing Child,
/// source, registrar or history. Its metadata is data; the actual opaque ticket,
/// original stored activation and installed source mechanism remain mandatory.
pub struct CnpSemanticCaptureScope<'a> {
    pub(super) source: &'a dyn CnpSemanticSource,
    pub(super) native: &'a mut CnpSemanticProcessCustody,
    pub(super) owner: &'a OwnerIdentity,
    pub(super) discovery: &'a DiscoverResult,
    pub(super) realization: &'a RealizeResult,
}

impl CnpSemanticCaptureScope<'_> {
    /// Captures the complete host controller with its actual supervisor loan.
    ///
    /// The opaque witness remains beside the same original controller. Both
    /// reservation/result slots retain their owning into-slot semantics, and
    /// this route creates no fresh connection or installation permission.
    ///
    /// # Errors
    /// Refuses changed source/current actor, an unsupported concrete supervisor,
    /// borrowed/missing original storage, unresolved I/O or exhausted bounds.
    /// Failure retains the witness and all reservation/completed owners.
    pub fn take_settled_original_complete_protocol_snapshot_into(
        &mut self,
        reservation: &mut Option<
            crucible_node_transport::protocol_snapshot::ProtocolSnapshotReservation,
        >,
        completed: &mut Option<
            crucible_node_transport::protocol_snapshot::OriginalProtocolSnapshot,
        >,
    ) -> Result<(), OperationFailure> {
        self.realization()?;
        self.native
            .retain_original_complete_protocol_supervisor()
            .map_err(unknown)?;
        self.realization()?;
        let call = ReadCall::begin(Rc::clone(&self.native.read_owner)).map_err(unknown)?;
        let result = (|| {
            if completed.is_some() {
                return Err(refused("complete original protocol result slot occupied"));
            }
            let witness = self
                .native
                .protocol_supervisor
                .try_borrow()
                .map_err(|_| refused("complete original supervisor witness borrowed"))?;
            let witness = witness
                .as_ref()
                .ok_or_else(|| refused("complete original supervisor witness absent"))?;
            let controller = self
                .native
                .controller
                .as_mut()
                .ok_or_else(|| refused("complete original protocol controller absent"))?;
            let cut = crucible_node_transport::protocol_snapshot::ProtocolCaptureCut::HostSettled;
            controller
                .capture_original_protocol_state_with_supervisor(
                    reservation
                        .as_mut()
                        .ok_or_else(|| refused("complete original protocol reservation absent"))?,
                    cut,
                    witness,
                )
                .map_err(unknown)?;
            controller
                .take_original_protocol_snapshot_into(reservation, completed, cut)
                .map_err(unknown)
        })();
        call.finish(result.is_ok());
        result?;
        if let Err(error) = self.realization() {
            self.native.ensure_origin().map_err(unknown)?;
            self.native.read_owner.revoke();
            return Err(super::after_effect(error));
        }
        Ok(())
    }

    /// Borrows the same independently installed complete source selection.
    pub fn installation(&self) -> &CnpSemanticInstallation {
        self.source.installation()
    }

    /// Authenticates and borrows the same actual Child and source realization.
    ///
    /// # Errors
    /// Refuses foreign creator process/thread, changed native resources, missing
    /// original controller or failed current source authentication.
    pub fn realization(&self) -> Result<CnpSemanticRealizationScope<'_>, OperationFailure> {
        self.native.authenticate_process().map_err(unknown)?;
        self.source.authenticate_provider(self.native)?;
        // Reauthenticate after the source callback before lending controller
        // references. A callback's own internal actions remain its responsibility.
        self.native.authenticate_process().map_err(unknown)?;
        Ok(CnpSemanticRealizationScope {
            installation: self.source.installation(),
            native: self.native,
            controller: self
                .native
                .controller
                .as_ref()
                .ok_or_else(|| refused("original capture controller is absent"))?,
            discovery: self.discovery,
            realization: self.realization,
        })
    }

    /// Retains the complete settled protocol on the same original controller.
    ///
    /// The caller supplies a reservation allocated and charged before native
    /// effects. This short loan never exposes the mutable controller. Its result
    /// is a protocol component; the source must join the actual original Capture
    /// response and all native prefix bytes before constructing its journal.
    ///
    /// # Errors
    /// Refuses a missing reservation, changed source/capsule, absent immutable
    /// native codec, partial or outstanding frames, or exhausted snapshot credit.
    /// Failure retains uncertainty and revokes the same original read owner.
    pub fn take_settled_original_protocol_snapshot(
        &mut self,
        reservation: &mut Option<
            crucible_node_transport::protocol_snapshot::ProtocolSnapshotReservation,
        >,
    ) -> Result<
        crucible_node_transport::protocol_snapshot::OriginalProtocolSnapshot,
        OperationFailure,
    > {
        self.realization()?;
        let call = ReadCall::begin(Rc::clone(&self.native.read_owner)).map_err(unknown)?;
        let result = (|| {
            let controller = self
                .native
                .controller
                .as_mut()
                .ok_or_else(|| refused("original protocol capture controller is absent"))?;
            let cut = crucible_node_transport::protocol_snapshot::ProtocolCaptureCut::HostSettled;
            controller
                .capture_original_protocol_state(
                    reservation
                        .as_mut()
                        .ok_or_else(|| refused("original protocol reservation is absent"))?,
                    cut,
                )
                .map_err(unknown)?;
            controller
                .take_original_protocol_snapshot(reservation, cut)
                .map_err(unknown)
        })();
        call.finish(result.is_ok());
        let snapshot = result?;
        if let Err(error) = self.realization() {
            self.native.ensure_origin().map_err(unknown)?;
            self.native.read_owner.revoke();
            return Err(super::after_effect(error));
        }
        Ok(snapshot)
    }

    /// Retains the settled protocol in a caller-owned slot before source rechecks.
    ///
    /// Both slots must already belong to the same source attempt. The SDK
    /// validates the reservation by borrow before moving it; the completed slot
    /// then retains the original snapshot even if this scope's final check fails.
    /// Neither snapshot completion nor matching bytes grants capture authority.
    ///
    /// # Errors
    /// Refuses changed original source/custody, an absent or already consumed
    /// reservation, an occupied result slot, unresolved protocol I/O or exhausted
    /// preallocated credit. Refusal retains the reservation or completed snapshot.
    pub fn take_settled_original_protocol_snapshot_into(
        &mut self,
        reservation: &mut Option<
            crucible_node_transport::protocol_snapshot::ProtocolSnapshotReservation,
        >,
        completed: &mut Option<
            crucible_node_transport::protocol_snapshot::OriginalProtocolSnapshot,
        >,
    ) -> Result<(), OperationFailure> {
        self.realization()?;
        let call = ReadCall::begin(Rc::clone(&self.native.read_owner)).map_err(unknown)?;
        let result = (|| {
            if completed.is_some() {
                return Err(refused("original protocol result slot is occupied"));
            }
            let controller = self
                .native
                .controller
                .as_mut()
                .ok_or_else(|| refused("original protocol capture controller is absent"))?;
            let cut = crucible_node_transport::protocol_snapshot::ProtocolCaptureCut::HostSettled;
            controller
                .capture_original_protocol_state(
                    reservation
                        .as_mut()
                        .ok_or_else(|| refused("original protocol reservation is absent"))?,
                    cut,
                )
                .map_err(unknown)?;
            controller
                .take_original_protocol_snapshot_into(reservation, completed, cut)
                .map_err(unknown)
        })();
        call.finish(result.is_ok());
        result?;

        if let Err(error) = self.realization() {
            self.native.ensure_origin().map_err(unknown)?;
            self.native.read_owner.revoke();
            return Err(super::after_effect(error));
        }
        Ok(())
    }

    /// Dispatches only the original administrative Capture through its controller.
    ///
    /// The operation and capture-owner fields come from the same opaque ticket.
    /// The source must precharge the complete request, response, content-transfer
    /// and settlement prefix before constructing the request. This method does
    /// not expose a mutable controller or permit replacement of its journals.
    ///
    /// # Errors
    /// Refuses foreign original ticket/current scope, mismatched complete capture
    /// arguments, unavailable original custody or uncertain controller dispatch.
    /// Uncertainty revokes this same read owner and retains the original capsule.
    pub fn call_original_capture(
        &mut self,
        ticket: &OriginalLineageOwnerCaptureTicket<'_>,
        record: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        request_id: crucible_node_format::Id,
        request: BeginRequest,
    ) -> Result<ResponseBody, OperationFailure> {
        let mut completed = None;
        self.call_original_capture_into(
            ticket,
            record,
            runtime_object,
            request_id,
            request,
            &mut completed,
        )?;
        completed.ok_or_else(|| refused("original Capture result was not retained"))
    }

    /// Retains the actual Capture reply before final original source checks.
    ///
    /// This uses the same ticket and controller path as `call_original_capture`.
    /// Failure or unwind after dispatch leaves the caller's completed result and
    /// original SDK journal intact; a new request or deadline is never inferred.
    ///
    /// # Errors
    /// Refuses an occupied result or every changed-ticket, currentness, budget
    /// and transport condition enforced by the original capture call.
    pub fn call_original_capture_into(
        &mut self,
        ticket: &OriginalLineageOwnerCaptureTicket<'_>,
        record: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        request_id: crucible_node_format::Id,
        request: BeginRequest,
        completed: &mut Option<ResponseBody>,
    ) -> Result<(), OperationFailure> {
        self.realization()?;
        if completed.is_some() {
            return Err(refused("original Capture result slot is occupied"));
        }
        let active = self
            .native
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.active.as_ref())
            .ok_or_else(|| refused("original capture activation is absent"))?;
        ticket
            .authenticate_scope(
                active,
                record,
                runtime_object,
                self.owner,
                &self.source.installation().owner.owner.participant_ids,
            )
            .map_err(|error| refused(error.to_string()))?;
        let BeginArguments::Capture(arguments) = request
            .decoded_arguments()
            .map_err(|error| refused(error.to_string()))?
        else {
            return Err(refused("original capture request has another action"));
        };
        if arguments.capture_id != *ticket.capture_id()
            || arguments.participant_ids != ticket.participants()
            || arguments.cut != ticket.cut()
            || arguments.event_ordinal != ticket.ordinal()
            || request.activation_id.0.as_ref() != Some(&active.record().activation_id)
            || request.world_generation != active.record().generation
            || request.binding_hash
                != self
                    .source
                    .installation()
                    .owner
                    .identity()
                    .map_err(unknown)?
            || request.owner_generation
                != self
                    .source
                    .installation()
                    .binding
                    .authority
                    .owner_generation
            || arguments.ordering_profile
                != self
                    .source
                    .installation()
                    .binding
                    .compatibility
                    .operating_contract
                    .ordering_profile
        {
            return Err(refused(
                "original capture request differs from its whole ticket",
            ));
        }
        let call = ReadCall::begin(Rc::clone(&self.native.read_owner)).map_err(unknown)?;
        let result = self
            .native
            .controller
            .as_mut()
            .ok_or_else(|| refused("original capture controller is absent"))?
            .call_original_capture(
                request_id,
                ticket.operation_id().clone(),
                ticket.owner().owner.clone(),
                request,
            )
            .map_err(unknown)
            .map(|response| *completed = Some(response));
        call.finish(result.is_ok());
        result?;
        if let Err(error) = self.realization() {
            // Dispatch already crossed the actual original channel. An exit
            // refusal cannot relabel that effect as never attempted. Foreign
            // processes return before touching this copied owner cell.
            self.native.ensure_origin().map_err(unknown)?;
            self.native.read_owner.revoke();
            return Err(super::after_effect(error));
        }
        Ok(())
    }
}

impl CnpSemanticNode {
    pub(super) fn capture_with_original_ticket(
        &mut self,
        ticket: &OriginalLineageOwnerCaptureTicket<'_>,
        activation: &WorldActivation,
        record: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        limits: NativeCaptureLimits,
    ) -> Result<InstalledOriginalLineageCapture, OperationFailure> {
        let mut completed = None;
        self.capture_with_original_ticket_into(
            ticket,
            activation,
            record,
            runtime_object,
            limits,
            &mut completed,
        )?;
        completed.ok_or_else(|| refused("original owning capture result absent"))
    }

    pub(super) fn capture_with_original_ticket_into(
        &mut self,
        ticket: &OriginalLineageOwnerCaptureTicket<'_>,
        activation: &WorldActivation,
        record: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        limits: NativeCaptureLimits,
        completed: &mut Option<InstalledOriginalLineageCapture>,
    ) -> Result<(), OperationFailure> {
        // Raw creator PID precedes thread-local affinity and any inherited cell.
        self.preparation.guard.custody().map_err(unknown)?;
        self.current()?;
        if completed.is_some() {
            return Err(refused("original owning capture destination is occupied"));
        }
        let source = self.source()?;
        let install = source.installation();
        if install.guarantees.capture_scope != crucible_node_format::CaptureScope::CompleteModel
            || install.guarantees.continuation != crucible_node_format::Continuation::Exact
        {
            return Err(refused(
                "generic source has no installed complete capture mechanism",
            ));
        }
        if let Some(scope) = ticket.restored_capture_scope17_data() {
            return self.capture_with_restored17_ticket_into(
                source.as_ref(),
                scope,
                ticket,
                activation,
                record,
                runtime_object,
                limits,
                completed,
            );
        }
        if source
            .requires_restored_capture17_scope_data()
            .map_err(unknown)?
        {
            return Err(refused(
                "selected Capture17 requires its actual current collecting scope",
            ));
        }
        let native = self
            .preparation
            .guard
            .custody
            .as_mut()
            .ok_or_else(|| refused("original capture native custody is absent"))?;
        native.authenticate_process().map_err(unknown)?;
        // This clones the original opaque handle, preserving its Rc authority;
        // it never reconstructs activation from the callback record.
        let active = native
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.active.as_ref())
            .cloned()
            .ok_or_else(|| refused("original capture has no independently stored activation"))?;
        if !active.same_authority(activation) {
            return Err(refused(
                "original capture belongs to another opaque activation",
            ));
        }
        let owner = self
            .route
            .owners
            .first()
            .filter(|_| self.route.owners.len() == 1)
            .ok_or_else(|| refused("original capture owner route is incomplete"))?;
        ticket
            .authenticate_scope(
                &active,
                record,
                runtime_object,
                owner,
                &install.owner.owner.participant_ids,
            )
            .map_err(|error| refused(error.to_string()))?;

        let result = source.capture_original_lineage_continuation_with_ticket_into(
            CnpSemanticCaptureScope {
                source: source.as_ref(),
                native,
                owner,
                discovery: &self.preparation.discovery,
                realization: &self.preparation.realization,
            },
            ticket,
            &active,
            record,
            runtime_object,
            limits,
            completed,
        );
        // An arbitrary source callback may not publish a copied parent result
        // or touch inherited node state after returning in another process.
        self.preparation.guard.custody().map_err(unknown)?;
        if result
            .as_ref()
            .is_err_and(|error| error.effects == crate::node_contract::EffectKnowledge::Unknown)
        {
            self.state_mut()?.quarantined = true;
        }
        result?;
        self.current()?;
        Ok(())
    }
}

/// Retains the finite request data for one separately selected confirmation.
///
/// This value owns no ticket or source authority. The actual capture scope must
/// independently authenticate the original ticket, capsule and installed codec.
pub struct CnpNativeAfterConfirmationCall {
    /// Supplies the new original controller request ID without renewing Capture.
    pub request_id: crucible_node_format::Id,
    /// Binds the previously completed Capture and its three original references.
    pub context: crucible_node_transport::reference_packet::service::confirmation::PacketNativeAfterConfirmationRequest,
}

impl CnpSemanticCaptureScope<'_> {
    /// Retains the selected confirmation result before rechecking its original source.
    ///
    /// The independent ticket and active capsule must match before the same
    /// controller dispatches the correlated Poll. Its SDK helper checks actual
    /// Capture correspondence and received fourth-object content. The returned
    /// data alone does not authenticate literal ACKs, settle the source journal,
    /// construct an installed capture or grant fresh restoration permission.
    ///
    /// The caller allocates and charges the result slot before dispatch. This
    /// method fills that slot before its final source check so a post-I/O refusal
    /// retains both the original controller history and returned receipt data.
    ///
    /// # Errors
    /// Refuses changed source or ticket custody, a foreign Capture context, an
    /// occupied result slot, an absent selected codec or uncertain transport.
    /// Uncertainty revokes the same original read owner without replacing it.
    pub fn call_original_native_after_confirmation_into(
        &mut self,
        ticket: &OriginalLineageOwnerCaptureTicket<'_>,
        record: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        request: CnpNativeAfterConfirmationCall,
        completed: &mut Option<(
            ResponseBody,
            crucible_node_transport::reference_packet::service::confirmation::PacketNativeAfterConfirmationReceipt,
        )>,
    ) -> Result<(), OperationFailure> {
        self.realization()?;
        if completed.is_some() {
            return Err(refused("original confirmation result slot is occupied"));
        }
        let active = self
            .native
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.active.as_ref())
            .ok_or_else(|| refused("original confirmation activation is absent"))?;
        ticket
            .authenticate_scope(
                active,
                record,
                runtime_object,
                self.owner,
                &self.source.installation().owner.owner.participant_ids,
            )
            .map_err(|error| refused(error.to_string()))?;
        let CnpNativeAfterConfirmationCall {
            request_id,
            context,
        } = request;
        context.validate_data().map_err(unknown)?;
        if context.capture_operation_id != *ticket.operation_id()
            || request_id == context.capture_request_id
        {
            return Err(refused(
                "original confirmation has another Capture operation",
            ));
        }

        let call = ReadCall::begin(Rc::clone(&self.native.read_owner)).map_err(unknown)?;
        let result: Result<(), OperationFailure> = (|| {
            let controller = self
                .native
                .controller
                .as_mut()
                .ok_or_else(|| refused("original confirmation controller is absent"))?;
            let result = controller
                .call_original_native_after_confirmation(
                    request_id,
                    ticket.owner().owner.clone(),
                    context,
                )
                .map_err(unknown)?;
            *completed = Some(result);
            Ok(())
        })();
        call.finish(result.is_ok());
        result?;

        if let Err(error) = self.realization() {
            self.native.ensure_origin().map_err(unknown)?;
            self.native.read_owner.revoke();
            return Err(super::after_effect(error));
        }
        Ok(())
    }
}
