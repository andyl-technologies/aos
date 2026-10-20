//! Retains separately assigned activation originals for the selected restore path.
//!
//! The borrowed target projection comes from the actual installed codec. It
//! cannot issue a phase claim, replace a genuine WorldActivation or authenticate
//! Source evidence. The same controller retains all assigned and partial owners.

mod upload;
pub(super) use upload::AssignedUpload;
pub use upload::{
    CompletedOriginalInstalledRestorationUpload, PreparedOriginalInstalledRestorationUpload,
};

use super::*;
use crate::operational_time::OperationalDeadline;
use crate::reference_packet::service::complete_restore::activation::*;
use crucible_node_format::HashRef;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ActivationState {
    Preparing,
    Unsigned,
    Sealing,
    Sealed,
    Publishing,
    Complete,
}

pub(super) struct AssignedOriginalInstalledRestorationActivation {
    command: PacketRestorationActivationCommand,
    request: PacketRestorationActivationRequest,
    unsigned_request: Option<Value>,
    original: Option<Envelope>,
    bytes: Vec<u8>,
    literal_slot: Option<usize>,
    cut: OperationalDeadline,
    state: ActivationState,
    response: Option<Envelope>,
}

/// Borrows the exact once-assigned activation before proof insertion or send.
#[must_use = "retain the same controller and its partial original through refusal"]
pub struct PreparedOriginalInstalledRestorationActivation<'a> {
    controller: &'a mut CnpController,
    phase: PacketRestorationActivationPhase,
}

/// Borrows the actual correlated terminal pair without issuing readiness.
pub struct CompletedOriginalInstalledRestorationActivation<'a> {
    phase: PacketRestorationActivationPhase,
    original: &'a Envelope,
    response: &'a Envelope,
}

impl CompletedOriginalInstalledRestorationActivation<'_> {
    /// Returns the phase of these exact retained originals.
    pub const fn phase_data(&self) -> PacketRestorationActivationPhase {
        self.phase
    }

    /// Borrows the complete actual assigned request, including its proof.
    pub const fn original(&self) -> &Envelope {
        self.original
    }

    /// Borrows the actual terminal retained before decoding and Source checks.
    pub const fn response(&self) -> &Envelope {
        self.response
    }
}

/// Borrows immutable target fields from the same installed native codec.
///
/// Neither these labels nor a copied DTO authenticate an activation. Source
/// compares this view with its retained launch and current completed Commit
/// under the original read fence before signing the separately admitted phase.
pub struct OriginalRestorationActivationTargetBindingData<'a> {
    /// Borrows the actual negotiated session.
    pub session: &'a Id,
    /// Borrows the actual negotiated incarnation.
    pub incarnation: &'a Id,
    /// Borrows the actual controller route's node.
    pub node: &'a Id,
    /// Borrows the actual indivisible execution owner.
    pub owner: &'a Id,
    /// Borrows the complete immutable owner binding, without hashing or cloning.
    pub owner_binding: &'a crucible_node_format::OwnerBinding,
    /// Borrows the actual prepared realization token.
    pub prepared_token: &'a Id,
    /// Borrows the actual independently installed admission.
    pub admission: &'a Id,
    /// Borrows the actual independently installed transaction.
    pub transaction: &'a Id,
    /// Borrows the actual physical gate label.
    pub gate: &'a Id,
    /// Borrows the actual immutable world binding hash.
    pub world: &'a HashRef,
}

impl CnpController {
    /// Names actual assignment, target-loan, conversion and partial-state views.
    pub fn original_installed_restoration_activation_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<OriginalRestorationActivationTargetBindingData<'static>>()
            + size_of::<
                Result<OriginalRestorationActivationTargetBindingData<'static>, ProviderError>,
            >()
            + size_of::<PreparedOriginalInstalledRestorationActivation<'static>>()
            + size_of::<
                Result<PreparedOriginalInstalledRestorationActivation<'static>, ProviderError>,
            >()
            + size_of::<CompletedOriginalInstalledRestorationActivation<'static>>()
            + size_of::<
                Result<CompletedOriginalInstalledRestorationActivation<'static>, ProviderError>,
            >()
            + size_of::<Option<&AssignedOriginalInstalledRestorationActivation>>()
            + size_of::<Option<&mut AssignedOriginalInstalledRestorationActivation>>()
            + size_of::<[Option<AssignedOriginalInstalledRestorationActivation>; 2]>()
            + size_of::<
                std::iter::Flatten<
                    std::slice::Iter<
                        'static,
                        Option<AssignedOriginalInstalledRestorationActivation>,
                    >,
                >,
            >()
            + restoration_activation_protocol_counter_scratch_data()
    }

    pub(super) fn ensure_no_pending_original_installed_restoration_activation(
        &self,
    ) -> Result<(), ProviderError> {
        if self
            .original_installed_restoration_activation
            .iter()
            .flatten()
            .any(|state| state.state != ActivationState::Complete)
        {
            return Err(refused());
        }
        for upload in self.original_installed_restoration_upload.iter().flatten() {
            upload.ensure_complete_data()?;
        }
        self.ensure_no_pending_original_installed_restoration_observation()
    }

    pub(crate) const fn original_installed_restoration_activation_owner_header_bytes_data() -> usize
    {
        std::mem::size_of::<AssignedOriginalInstalledRestorationActivation>()
    }

    pub(crate) fn authenticate_original_installed_activation_launch_data(
        &self,
        launch: &crate::reference_packet::service::PacketNative5SourceLaunch,
    ) -> Result<*const (), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        let selected = self.session.fresh_restore_query_selection()?;
        authenticate_restoration_activation_selection_data(selected, self.authority())?;
        if selected != &launch.selection || self.authority().limits() != launch.limits {
            return Err(refused());
        }
        Ok(std::rc::Rc::as_ptr(&self.protocol_owner).cast())
    }

    /// Checks an actual completed activation's complete native proof chain.
    ///
    /// The caller retains the decoded restored record and returned underlying
    /// owner before later Source checks. Source still validates its current
    /// private association, MAC, real scope proof and kernel child under the
    /// same read fence. Neither decoding nor this DATA check creates readiness.
    ///
    /// # Errors
    /// Refuses a partial/foreign phase, altered Commit/capture/mapping/context,
    /// changed physical-held state, wrong native PID or any changed full actual
    /// original/owner/model proof. Content references must be verified separately.
    pub fn authenticate_original_installed_restoration_activation_evidence_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        phase: PacketRestorationActivationPhase,
        record: &crate::reference_packet::service::complete_restore::PacketNativeRestoredRecord,
        underlying: &[u8],
    ) -> Result<crate::reference_packet::control::PacketNative5UnderlyingRecord, ProviderError>
    {
        let completed = self.original_completed_installed_restoration_activation(emitter, phase)?;
        let state = self.activation_slot(phase).as_ref().ok_or_else(refused)?;
        let scope = &state.request.scope;
        record.validate_data()?;
        if record.captured_owner_state != scope.restoration.captured_owner_state
            || record.captured_journal != scope.restoration.captured_journal
            || record.mapping != scope.restoration.mapping
            || record.restore_commit != scope.restoration.commit_request
            || record.restore_response != scope.restoration.commit_response
            || record.context_digest != scope.restoration.context_digest
            || record.physical_gate_held != (phase == PacketRestorationActivationPhase::Arm)
            || scope.target.native_pid.get() != u64::from(self.peer_pid())
        {
            return Err(refused());
        }
        let selection = self.session.fresh_restore_query_selection()?;
        authenticate_restoration_activation_selection_data(selection, self.authority())?;
        record.native_receipt.verify_original_record_data(
            selection,
            self.peer_pid(),
            completed.original(),
            underlying,
        )
    }

    fn activation_slot(
        &self,
        phase: PacketRestorationActivationPhase,
    ) -> &Option<AssignedOriginalInstalledRestorationActivation> {
        &self.original_installed_restoration_activation[phase_index(phase)]
    }

    /// Assigns one separately admitted activation without changing its cut later.
    ///
    /// The Source must own a genuine once phase claim and retain its independent
    /// construction owners. This method authenticates actual SDK ownership and
    /// finite wire geometry; only native MAC/phase validation permits effects.
    ///
    /// # Errors
    /// Refuses another actor, unselected schema, mismatched target or command,
    /// reused phase/ID, absent Commit, unfinished prior Arm, exhausted actual
    /// frame/journal banks or insufficient separately produced storage DATA.
    pub fn prepare_original_installed_restoration_activation<'a>(
        &'a mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        request_id: Id,
        command: PacketRestorationActivationCommand,
        request: PacketRestorationActivationRequest,
        admitted: &OriginalInstalledRestorationActivationConstructionData,
    ) -> Result<PreparedOriginalInstalledRestorationActivation<'a>, ProviderError> {
        emitter.authenticate_original(self)?;
        self.ensure_no_pending_original_ack_admit()?;
        self.ensure_no_pending_original_complete_restore()?;
        admitted.authenticate_controller_data(std::rc::Rc::as_ptr(&self.protocol_owner).cast())?;
        authenticate_activation_allocation_data(
            &request.native_allocation,
            &admitted.native_allocation_data(request.phase),
        )?;
        self.original_installed_restoration_activation_target_binding_data()?
            .authenticate_request_data(&request)?;
        command.authenticate_request_data(&request)?;
        let phase = request.phase;
        if self.activation_slot(phase).is_some() || self.original(&request_id).is_some() {
            return Err(refused());
        }
        self.original_completed_complete_restore_transfer(
            emitter, crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreTransferPhase::Commit,
        )?;
        if phase == PacketRestorationActivationPhase::WorldActivate {
            self.original_completed_installed_restoration_activation(
                emitter,
                PacketRestorationActivationPhase::Arm,
            )?;
            let PacketRestorationActivationCommand::WorldActivate(body) = &command else {
                return Err(refused());
            };
            for upload in &self.original_installed_restoration_upload {
                upload
                    .as_ref()
                    .ok_or_else(refused)?
                    .authenticate_completed_world_data(&request.scope, &body.activation_manifest)?;
            }
        }
        let maximum = self.maximum_frame()?;
        let (sequence, cut) = self.session.begin_original_ack_admit(self.budget)?;
        let state = &mut self.original_installed_restoration_activation[phase_index(phase)];
        *state = Some(AssignedOriginalInstalledRestorationActivation {
            command,
            request,
            unsigned_request: None,
            original: None,
            bytes: Vec::new(),
            literal_slot: None,
            cut,
            state: ActivationState::Preparing,
            response: None,
        });
        let state = state.as_mut().ok_or_else(refused)?;
        state.unsigned_request = Some(
            serde_json::to_value(&state.request)
                .map_err(crucible_node_format::ContractError::from)?,
        );
        let body = match &state.command {
            PacketRestorationActivationCommand::Arm(body) => serde_json::to_value(body),
            PacketRestorationActivationCommand::WorldActivate(body) => serde_json::to_value(body),
        }
        .map_err(crucible_node_format::ContractError::from)?;
        let Value::Object(body) = body else {
            return Err(refused());
        };
        let mut unsigned = serde_json::Map::new();
        unsigned.insert(
            "request".into(),
            state.unsigned_request.take().ok_or_else(refused)?,
        );
        let mut extensions = Extensions::new();
        extensions.insert(
            PACKET_RESTORATION_ACTIVATION_FEATURE.into(),
            Value::Object(unsigned),
        );
        state.original = Some(Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(self.session.authority().session_id().clone())),
            incarnation_id: Nullable(Some(self.session.authority().incarnation_id().clone())),
            node_id: Nullable(Some(self.route.node.clone())),
            execution_owner_id: Nullable(Some(self.route.execution_owner.clone())),
            capture_owner_id: Nullable(None),
            operation_id: Nullable(None),
            request_id: Nullable(Some(request_id)),
            sequence,
            method: phase.method(),
            body,
            extensions,
        });
        let original = state.original.as_ref().ok_or_else(refused)?;
        // Exact closed proof geometry is independently bounded. The unchanged
        // full frame ceiling also applies after insertion in seal().
        let proof_room = maximum_restoration_activation_proof_encoded_bytes_data()?;
        let final_maximum = crate::connection::serialized_credit(original, maximum)?
            .checked_add(proof_room)
            .and_then(|n| n.checked_add(9))
            .filter(|n| *n <= maximum)
            .ok_or_else(credit)?;
        state
            .bytes
            .try_reserve_exact(final_maximum)
            .map_err(|_| credit())?;
        self.session
            .reserve_original_installed_restoration_activation(
                original,
                final_maximum,
                &mut state.literal_slot,
            )?;
        state.state = ActivationState::Unsigned;
        Ok(PreparedOriginalInstalledRestorationActivation {
            controller: self,
            phase,
        })
    }

    /// Borrows an actual completed phase, preserving its original history.
    ///
    /// # Errors
    /// Refuses another emitter/actor, missing or unfinished phase, or a terminal
    /// that does not correlate with the exact retained signed original.
    pub fn original_completed_installed_restoration_activation(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        phase: PacketRestorationActivationPhase,
    ) -> Result<CompletedOriginalInstalledRestorationActivation<'_>, ProviderError> {
        emitter.authenticate_original(self)?;
        let state = self.activation_slot(phase).as_ref().ok_or_else(refused)?;
        if state.state != ActivationState::Complete {
            return Err(refused());
        }
        let original = state.original.as_ref().ok_or_else(refused)?;
        let response = state.response.as_ref().ok_or_else(refused)?;
        original.matches_response(response)?;
        Ok(CompletedOriginalInstalledRestorationActivation {
            phase,
            original,
            response,
        })
    }

    /// Borrows actual target fields without renewing a query or protocol frontier.
    ///
    /// Source still authenticates its complete launch, current Commit/Hold and
    /// owner-binding hash. This method uses precredited fixed schema hashing,
    /// performs no allocation, callback, serialization or I/O, and returns no
    /// controller or general codec owner.
    ///
    /// # Errors
    /// Refuses a foreign/revoked actor, missing selected fresh codec, altered or
    /// unnegotiated activation schema, or a route outside the sole actual owner.
    pub fn original_installed_restoration_activation_target_binding_data(
        &self,
    ) -> Result<OriginalRestorationActivationTargetBindingData<'_>, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        let selection = self.session.fresh_restore_query_selection()?;
        authenticate_restoration_activation_selection_data(selection, self.authority())?;
        let [owner_binding] = selection.realization.owner_bindings.as_slice() else {
            return Err(refused());
        };
        if owner_binding.owner.id != self.route.execution_owner
            || !owner_binding
                .owner
                .participant_ids
                .contains(&self.route.node)
        {
            return Err(refused());
        }
        Ok(OriginalRestorationActivationTargetBindingData {
            session: self.authority().session_id(),
            incarnation: self.authority().incarnation_id(),
            node: &self.route.node,
            owner: &self.route.execution_owner,
            owner_binding,
            prepared_token: &selection.prepared_token,
            admission: &selection.admission,
            transaction: &selection.transaction,
            gate: &selection.gate,
            world: &selection.world,
        })
    }
}

impl AssignedOriginalInstalledRestorationActivation {
    pub(super) fn observe_owned_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            command,
            request,
            unsigned_request,
            original,
            bytes,
            literal_slot: _,
            cut: _,
            state,
            response,
        } = self;
        match state {
            ActivationState::Preparing
            | ActivationState::Unsigned
            | ActivationState::Sealing
            | ActivationState::Sealed
            | ActivationState::Publishing
            | ActivationState::Complete => {}
        }
        observer.observe(command)?;
        observer.observe(request)?;
        observer.observe(unsigned_request)?;
        observer.observe(original)?;
        observer.vector::<u8>(bytes.capacity())?;
        observer.observe(response)
    }
}

impl OriginalRestorationActivationTargetBindingData<'_> {
    /// Compares all borrowed immutable target labels to the signed request DATA.
    ///
    /// The native PID, owner generation, binding hash and genuine activation
    /// remain separately checked against actual authenticated Source evidence.
    ///
    /// # Errors
    /// Refuses any changed session, incarnation, route or preparation label.
    pub fn authenticate_request_data(
        &self,
        request: &PacketRestorationActivationRequest,
    ) -> Result<(), ProviderError> {
        self.authenticate_scope_data(&request.scope)
    }

    pub(super) fn authenticate_scope_data(
        &self,
        scope: &PacketRestorationActivationScope,
    ) -> Result<(), ProviderError> {
        let target = &scope.target;
        if self.session != &target.session
            || self.incarnation != &target.incarnation
            || self.node != &target.node
            || self.owner != &target.owner
            || self.prepared_token != &target.prepared_token
            || self.admission != &target.admission
            || self.transaction != &target.transaction
            || self.gate != &target.gate
            || self.world != &target.world
        {
            return Err(refused());
        }
        Ok(())
    }
}

impl PreparedOriginalInstalledRestorationActivation<'_> {
    /// Borrows this marker's completed original pair without advancing history.
    ///
    /// # Errors
    /// Refuses another emitter, an incomplete phase or mismatched terminal.
    pub fn completed_original(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<CompletedOriginalInstalledRestorationActivation<'_>, ProviderError> {
        self.controller
            .original_completed_installed_restoration_activation(emitter, self.phase)
    }

    /// Borrows the actual assigned original without renewing its cut or sequence.
    ///
    /// # Errors
    /// Refuses a foreign/revoked controller, missing partial owner or expired cut.
    pub fn original(&self) -> Result<&Envelope, ProviderError> {
        self.controller.protocol_owner.ensure_current()?;
        let state = self
            .controller
            .activation_slot(self.phase)
            .as_ref()
            .ok_or_else(refused)?;
        let original = state.original.as_ref().ok_or_else(refused)?;
        if state.state != ActivationState::Complete {
            self.controller
                .session
                .authenticate_original_ack_admit_cut(original.sequence, state.cut)?;
        }
        Ok(original)
    }

    /// Inserts only the proof into the exact once-assigned unsigned request.
    ///
    /// # Errors
    /// Refuses another emitter/cut, repeated sealing, a changed unsigned request,
    /// a proof not bound to this actual assigned digest or the full frame cap.
    pub fn seal(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        artifact: PacketRestorationActivationArtifact,
    ) -> Result<(), ProviderError> {
        emitter.authenticate_original(self.controller)?;
        let maximum = self.controller.maximum_frame()?;
        let assigned =
            restoration_activation_assigned_request_digest(self.original()?, self.phase, maximum)?;
        artifact.validate_data()?;
        let state = self.controller.original_installed_restoration_activation
            [phase_index(self.phase)]
        .as_mut()
        .ok_or_else(refused)?;
        if state.state != ActivationState::Unsigned || artifact.request != state.request {
            return Err(refused());
        }
        let context = PacketRestorationActivationContext {
            request: artifact.request.clone(),
            assigned_request: crucible_node_format::Bytes::new(assigned.to_vec()),
        };
        if restoration_activation_context_digest_data(&context)?.as_slice()
            != artifact.proof.context_digest.as_slice()
        {
            return Err(refused());
        }
        state.state = ActivationState::Sealing;
        let original = state.original.as_mut().ok_or_else(refused)?;
        let unsigned = original
            .extensions
            .get_mut(PACKET_RESTORATION_ACTIVATION_FEATURE)
            .and_then(Value::as_object_mut)
            .ok_or_else(refused)?;
        if unsigned.len() != 1 || !unsigned.contains_key("request") {
            return Err(refused());
        }
        unsigned.insert(
            "proof".into(),
            serde_json::to_value(artifact.proof)
                .map_err(crucible_node_format::ContractError::from)?,
        );
        crate::connection::serialized_credit(original, maximum)?;
        self.controller.session.seal_original_ack_admit(
            &mut self.controller.custody,
            original,
            &mut state.bytes,
            state.literal_slot,
        )?;
        state.state = ActivationState::Sealed;
        Ok(())
    }

    /// Publishes the same original and retains its terminal before any decode.
    ///
    /// # Errors
    /// Refuses a reused/unfinished phase, occupied output, stale cut or protocol
    /// error. The sticky attempt and all partial original owners remain retained.
    pub fn publish_into(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        completed: &mut Option<ResponseBody>,
    ) -> Result<(), ProviderError> {
        emitter.authenticate_original(self.controller)?;
        self.original()?;
        if completed.is_some() {
            return Err(refused());
        }
        let state = self.controller.original_installed_restoration_activation
            [phase_index(self.phase)]
        .as_mut()
        .ok_or_else(refused)?;
        if state.state != ActivationState::Sealed {
            return Err(refused());
        }
        state.state = ActivationState::Publishing;
        let original = state.original.as_ref().ok_or_else(refused)?;
        state.response = Some(
            self.controller
                .session
                .publish_original_installed_restoration_activation(
                    &mut self.controller.custody,
                    original,
                    &state.bytes,
                    state.literal_slot,
                    state.cut,
                )?,
        );
        let response = state.response.as_ref().ok_or_else(refused)?;
        original.matches_response(response)?;
        let request = decode_request(original.method, &original.body)?;
        *completed = Some(decode_response(&request, &response.body)?);
        state.state = ActivationState::Complete;
        Ok(())
    }
}

const fn phase_index(phase: PacketRestorationActivationPhase) -> usize {
    match phase {
        PacketRestorationActivationPhase::Arm => 0,
        PacketRestorationActivationPhase::WorldActivate => 1,
    }
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("installed restoration activation original credit")
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original installed restoration activation changed")
}

fn authenticate_activation_allocation_data(
    actual: &PacketRestorationActivationAllocationRow,
    admitted: &PacketRestorationActivationAllocationRow,
) -> Result<(), ProviderError> {
    if actual != admitted {
        return Err(refused());
    }
    Ok(())
}

#[cfg(test)]
mod admitted_axis_tests {
    use super::*;

    #[test]
    fn assigned_activation_rejects_each_changed_axis_even_with_equal_whole_sum() {
        let admitted = PacketRestorationActivationAllocationRow {
            retained_requested_bytes: U64::new(10),
            maximum_simultaneous_transient_bytes: U64::new(20),
            declared_counter_scratch_bytes: U64::new(30),
        };
        assert!(authenticate_activation_allocation_data(&admitted, &admitted).is_ok());
        for actual in [
            PacketRestorationActivationAllocationRow {
                retained_requested_bytes: U64::new(11),
                maximum_simultaneous_transient_bytes: U64::new(19),
                ..admitted
            },
            PacketRestorationActivationAllocationRow {
                maximum_simultaneous_transient_bytes: U64::new(21),
                declared_counter_scratch_bytes: U64::new(29),
                ..admitted
            },
            PacketRestorationActivationAllocationRow {
                declared_counter_scratch_bytes: U64::new(31),
                retained_requested_bytes: U64::new(9),
                ..admitted
            },
        ] {
            assert_eq!(
                actual.requested_bytes_data().unwrap(),
                admitted.requested_bytes_data().unwrap()
            );
            assert!(authenticate_activation_allocation_data(&actual, &admitted).is_err());
        }
    }
}

impl AssignedOriginalInstalledRestorationActivation {
    pub(super) fn borrowed_settled_history_data(&self) -> impl serde::Serialize + '_ {
        let Self {
            command,
            request,
            unsigned_request,
            original,
            bytes,
            literal_slot,
            cut: _,
            state,
            response,
        } = self;
        (
            "source-private.sdk-activation-current/17",
            crate::reference_packet::service::complete_restore::activation::HistoricalRestorationActivationData::Command(command),
            request, unsigned_request, original,
            crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::new(bytes),
            bytes.capacity(), literal_slot,
            match state { ActivationState::Preparing => "preparing", ActivationState::Unsigned => "unsigned", ActivationState::Sealing => "sealing", ActivationState::Sealed => "sealed", ActivationState::Publishing => "publishing", ActivationState::Complete => "complete" },
            response, "historical-nonrenewable-operational-cut",
        )
    }
}

fn settled_field_views<T>(
    _: impl FnOnce(&'static AssignedOriginalInstalledRestorationActivation) -> T,
) -> usize {
    std::mem::size_of::<T>()
}

impl AssignedOriginalInstalledRestorationActivation {
    pub(super) fn settled_history_counter_scratch_data() -> usize {
        settled_field_views(|value| {
            let projected = value.borrowed_settled_history_data();
            (projected, Some(value.borrowed_settled_history_data()))
        }) + settled_field_views(|value| {
            let AssignedOriginalInstalledRestorationActivation {
                command,
                request,
                unsigned_request,
                original,
                bytes,
                literal_slot,
                cut,
                state,
                response,
            } = value;
            (
                command,
                request,
                unsigned_request,
                original,
                bytes,
                literal_slot,
                cut,
                state,
                response,
            )
        }) + std::mem::size_of::<&Self>()
            + std::mem::size_of::<Option<&Self>>()
            + std::mem::size_of::<&mut crate::retained_metadata::MetadataObserver<'static>>()
            + std::mem::size_of::<Result<(), ProviderError>>()
    }
}
