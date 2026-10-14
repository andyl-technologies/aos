//! Owns ticketed capture loans over the same original CNP process capsule.
//!
//! This forwarding route does not install a preservation mechanism. Legacy
//! sources retain CaptureNone, and the source callback refuses by default.
//! A selected native mechanism must independently authenticate its complete
//! snapshot and original administrative request/response settlement.

use std::rc::Rc;

use crucible_node_provider::bodies::{
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
            crucible_node_provider::protocol_snapshot::ProtocolSnapshotReservation,
        >,
    ) -> Result<crucible_node_provider::protocol_snapshot::OriginalProtocolSnapshot, OperationFailure>
    {
        self.realization()?;
        let call = ReadCall::begin(Rc::clone(&self.native.read_owner)).map_err(unknown)?;
        let result = (|| {
            let controller = self
                .native
                .controller
                .as_mut()
                .ok_or_else(|| refused("original protocol capture controller is absent"))?;
            let cut = crucible_node_provider::protocol_snapshot::ProtocolCaptureCut::HostSettled;
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
            crucible_node_provider::protocol_snapshot::ProtocolSnapshotReservation,
        >,
        completed: &mut Option<crucible_node_provider::protocol_snapshot::OriginalProtocolSnapshot>,
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
            let cut = crucible_node_provider::protocol_snapshot::ProtocolCaptureCut::HostSettled;
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
        request_id: crucible_node_contract::Id,
        request: BeginRequest,
    ) -> Result<ResponseBody, OperationFailure> {
        self.realization()?;
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
            .map_err(unknown);
        call.finish(result.is_ok());
        let response = result?;
        if let Err(error) = self.realization() {
            // Dispatch already crossed the actual original channel. An exit
            // refusal cannot relabel that effect as never attempted. Foreign
            // processes return before touching this copied owner cell.
            self.native.ensure_origin().map_err(unknown)?;
            self.native.read_owner.revoke();
            return Err(super::after_effect(error));
        }
        Ok(response)
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
        // Raw creator PID precedes thread-local affinity and any inherited cell.
        self.preparation.guard.custody().map_err(unknown)?;
        self.current()?;
        let source = self.source()?;
        let install = source.installation();
        if install.guarantees.capture_scope != crucible_node_contract::CaptureScope::CompleteModel
            || install.guarantees.continuation != crucible_node_contract::Continuation::Exact
        {
            return Err(refused(
                "generic source has no installed complete capture mechanism",
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

        let result = source.capture_original_lineage_continuation_with_ticket(
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
        let result = result?;
        self.current()?;
        Ok(result)
    }
}
