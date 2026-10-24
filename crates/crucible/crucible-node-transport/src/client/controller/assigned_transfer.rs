//! Retains distinct original prepare and commit slots for one restore transaction.
//!
//! Each phase receives its own actual operation cut once. Reborrowing a slot
//! never renews that cut, sequence, request ID, bank or proof. The original eleven
//! path and its stricter mapping-creation-cut check remain separate.

use super::assigned_restore::{AssignedOriginalCompleteRestore, Phase};
use super::*;
use crate::reference_packet::service::fresh_restore_allocation::{
    PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING, PacketNative5FreshRestoreAllocationSelection,
    PacketNativeFreshRestoreAllocationPrepareBinding,
};

use crate::protocol_snapshot::PreparedArchivedProtocolMapping;
use crate::reference_packet::service::complete_restore::transfer::*;
use serde::Deserialize;
use serde_json::Map;

mod construction_storage;
mod fresh_prepare;
mod held_prefix_storage;
pub use fresh_prepare::{
    OriginalFreshRestorePrepareBindingStorageData, OriginalFreshRestorePrepareInputs,
};

/// Borrows one actual phase-assigned restore original without moving its owners.
#[must_use = "the exact original remains in its controller when this loan ends"]
pub struct PreparedOriginalCompleteRestoreTransfer<'a> {
    controller: &'a mut CnpController,
    phase: PacketCompleteRestoreTransferPhase,
}

/// Borrows both actual completed phase originals without issuing an install right.
pub struct CompletedOriginalCompleteRestoreTransfer<'a> {
    phase: PacketCompleteRestoreTransferPhase,
    original: &'a Envelope,
    response: &'a Envelope,
}

impl CompletedOriginalCompleteRestoreTransfer<'_> {
    /// Returns the independently assigned phase.
    pub const fn phase(&self) -> PacketCompleteRestoreTransferPhase {
        self.phase
    }
    /// Borrows the exact request with actual sequence and stored proof.
    pub const fn original(&self) -> &Envelope {
        self.original
    }
    /// Borrows the actual correlated reply with its original receipt.
    pub const fn response(&self) -> &Envelope {
        self.response
    }
}

struct TransferPreparation {
    request_id: Id,
    baseline: BeginRequest,
    value: Value,
    phase: PacketCompleteRestoreTransferPhase,
    reference: ContentRef,
    extensions: TransferExtensions,
}

enum TransferExtensions {
    PhaseOnly,
    FreshPrepare(PacketNativeFreshRestoreAllocationPrepareBinding),
}

impl CnpController {
    fn transfer_slot(
        &self,
        phase: PacketCompleteRestoreTransferPhase,
    ) -> &Option<AssignedOriginalCompleteRestore> {
        match phase {
            PacketCompleteRestoreTransferPhase::Prepare => &self.original_complete_restore_prepare,
            PacketCompleteRestoreTransferPhase::Commit => &self.original_complete_restore_commit,
        }
    }

    fn transfer_slot_mut(
        &mut self,
        phase: PacketCompleteRestoreTransferPhase,
    ) -> &mut Option<AssignedOriginalCompleteRestore> {
        match phase {
            PacketCompleteRestoreTransferPhase::Prepare => {
                &mut self.original_complete_restore_prepare
            }
            PacketCompleteRestoreTransferPhase::Commit => {
                &mut self.original_complete_restore_commit
            }
        }
    }

    /// Assigns the exact pretransport prepare before lending it to the source signer.
    ///
    /// # Errors
    /// Refuses another source mechanism, stale actual emitter/mapping, reused
    /// phase or ID, invalid finite wire data, baseline kind or original credit.
    pub fn prepare_original_complete_restore_prepare<'a>(
        &'a mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        request_id: Id,
        baseline: BeginRequest,
        request: PacketCompleteRestorePrepareRequest,
        mapping: &PreparedArchivedProtocolMapping,
    ) -> Result<PreparedOriginalCompleteRestoreTransfer<'a>, ProviderError> {
        request.validate_data()?;
        if &request.host_protocol != mapping.archive_protocol()
            || &request.native_protocol != mapping.native_protocol()
            || request.restoration.nonce.as_slice() != mapping.nonce()
        {
            return Err(refused());
        }
        authenticate_mapping_reference(&request.restoration.mapping, mapping)?;
        let value =
            serde_json::to_value(&request).map_err(crucible_node_format::ContractError::from)?;
        self.prepare_transfer(
            emitter,
            mapping,
            TransferPreparation {
                request_id,
                baseline,
                value,
                phase: PacketCompleteRestoreTransferPhase::Prepare,
                reference: request.restoration.mapping,
                extensions: TransferExtensions::PhaseOnly,
            },
        )
    }

    /// Assigns commit only after the actual same prepare reply has completed.
    ///
    /// # Errors
    /// Refuses a changed prepare body, ID, sequence, full original/response hash,
    /// lease token, mapping, phase, emitter or insufficient original credit.
    pub fn prepare_original_complete_restore_commit<'a>(
        &'a mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        request_id: Id,
        baseline: BeginRequest,
        request: PacketCompleteRestoreCommitRequest,
        mapping: &PreparedArchivedProtocolMapping,
    ) -> Result<PreparedOriginalCompleteRestoreTransfer<'a>, ProviderError> {
        emitter.authenticate_original(self)?;
        self.authenticate_archived_protocol_transfer_mapping(mapping)?;
        request.validate_data()?;
        let maximum = self.maximum_frame()?;
        let prior = self
            .original_complete_restore_prepare
            .as_ref()
            .ok_or_else(refused)?;
        prior.validate_owned_snapshot()?;
        mapping.authenticate_identity(&prior.mapping_identity)?;
        let reply = prior.response.as_ref().ok_or_else(refused)?;
        let prepare_value = serde_json::to_value(&request.prepare)
            .map_err(crucible_node_format::ContractError::from)?;
        if prior
            .original
            .extensions
            .get(PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION)
            != Some(&prepare_value)
            || prior.original.request_id.0.as_ref() != Some(&request.prepare_request_id)
            || prior.original.sequence != request.prepare_request_sequence
            || reply.sequence != request.prepare_response_sequence
            || complete_restore_transfer_original_digest(&prior.original, maximum)?.as_slice()
                != request.prepare_request_digest.as_slice()
            || complete_restore_transfer_original_digest(reply, maximum)?.as_slice()
                != request.prepare_response_digest.as_slice()
            || prior.nonce != *mapping.nonce()
        {
            return Err(refused());
        }
        let receipt_value = reply
            .extensions
            .get(PACKET_COMPLETE_RESTORE_PREPARE_RECEIPT_EXTENSION)
            .ok_or_else(refused)?;
        let receipt = PacketCompleteRestorePrepareReceipt::deserialize(receipt_value)
            .map_err(crucible_node_format::ContractError::from)?;
        receipt.validate_data()?;
        if receipt.transfer_token != request.transfer_token
            || receipt.generation != request.prepare.generation
            || receipt.native_sequence != reply.sequence
        {
            return Err(refused());
        }
        let mapping_reference = request.prepare.restoration.mapping.clone();
        let value =
            serde_json::to_value(&request).map_err(crucible_node_format::ContractError::from)?;
        self.prepare_transfer(
            emitter,
            mapping,
            TransferPreparation {
                request_id,
                baseline,
                value,
                phase: PacketCompleteRestoreTransferPhase::Commit,
                reference: mapping_reference,
                extensions: TransferExtensions::PhaseOnly,
            },
        )
    }

    fn prepare_transfer<'a>(
        &'a mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        mapping: &PreparedArchivedProtocolMapping,
        preparation: TransferPreparation,
    ) -> Result<PreparedOriginalCompleteRestoreTransfer<'a>, ProviderError> {
        let TransferPreparation {
            request_id,
            baseline,
            value,
            phase,
            reference,
            extensions: selected_extensions,
        } = preparation;
        emitter.authenticate_original(self)?;
        self.ensure_no_pending_original_ack_admit()?;
        self.ensure_no_pending_original_complete_restore()?;
        self.authenticate_archived_protocol_transfer_mapping(mapping)?;
        if self.original_complete_restore.is_some()
            || self.transfer_slot(phase).is_some()
            || self.original(&request_id).is_some()
            || !baseline.extensions.is_empty()
            || !matches!(
                baseline.decoded_arguments()?,
                BeginArguments::PrepareRestore(_)
            )
        {
            return Err(refused());
        }
        for key in [
            phase.request_extension(),
            phase.proof_extension(),
            phase.receipt_extension(),
        ] {
            if !self.authority().envelope_extensions().contains(key) {
                return Err(refused());
            }
        }
        baseline.validate()?;
        let maximum = self.maximum_frame()?;
        count_serialized(&baseline, maximum)?;
        let Value::Object(body) =
            serde_json::to_value(baseline).map_err(crucible_node_format::ContractError::from)?
        else {
            return Err(refused());
        };
        let mut extensions = Extensions::new();
        extensions.insert(phase.request_extension().into(), value);
        if let TransferExtensions::FreshPrepare(binding) = selected_extensions {
            if phase != PacketCompleteRestoreTransferPhase::Prepare
                || self.original_native5_fresh_restore_allocation_selection()?
                    != Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
                || !self
                    .authority()
                    .envelope_extensions()
                    .contains(PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING)
            {
                return Err(refused());
            }
            binding.validate_data()?;
            extensions.insert(
                PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING.into(),
                serde_json::to_value(binding).map_err(crucible_node_format::ContractError::from)?,
            );
        }
        // This reset belongs only to creation of this previously absent phase.
        // Resume/seal/publish authenticate the stored cut and never call reset.
        let (sequence, cut) = self.session.begin_original_ack_admit(self.budget)?;
        let original = assigned_transfer_original(
            self.authority(),
            &self.route,
            request_id,
            sequence,
            body,
            extensions,
        );
        let final_maximum = crate::connection::serialized_credit(&original, maximum)?
            .checked_add(phase.proof_extension().len() + 3)
            .and_then(|n| n.checked_add(MAXIMUM_COMPLETE_RESTORE_TRANSFER_PROOF_BYTES))
            .filter(|n| *n <= maximum)
            .ok_or_else(credit)?;
        self.preflight_source_reply(
            1,
            0,
            final_maximum.checked_add(maximum).ok_or_else(credit)?,
            0,
            0,
        )?;
        *self.transfer_slot_mut(phase) = Some(AssignedOriginalCompleteRestore {
            original,
            bytes: Vec::new(),
            literal_slot: None,
            cut,
            phase: Phase::Unsigned,
            response: None,
            mapping: reference,
            mapping_identity: mapping.retain_identity(),
            nonce: *mapping.nonce(),
        });
        let state = self.transfer_slot_mut(phase).as_mut().ok_or_else(refused)?;
        state
            .bytes
            .try_reserve_exact(final_maximum)
            .map_err(|_| credit())?;
        // Split the disjoint controller fields so the retained owner remains in
        // its slot if original-bank reservation fails or unwinds.
        let (session, slot) = match phase {
            PacketCompleteRestoreTransferPhase::Prepare => (
                &mut self.session,
                &mut self.original_complete_restore_prepare,
            ),
            PacketCompleteRestoreTransferPhase::Commit => (
                &mut self.session,
                &mut self.original_complete_restore_commit,
            ),
        };
        let state = slot.as_mut().ok_or_else(refused)?;
        session.reserve_original_complete_restore_transfer(
            &state.original,
            final_maximum,
            &mut state.literal_slot,
        )?;
        Ok(PreparedOriginalCompleteRestoreTransfer {
            controller: self,
            phase,
        })
    }

    /// Reborrows only the same unsigned or sealed phase without cut renewal.
    ///
    /// # Errors
    /// Refuses missing/attempted phases, another emitter or expired original cut.
    pub fn resume_original_complete_restore_transfer<'a>(
        &'a mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        phase: PacketCompleteRestoreTransferPhase,
    ) -> Result<PreparedOriginalCompleteRestoreTransfer<'a>, ProviderError> {
        emitter.authenticate_original(self)?;
        let state = self.transfer_slot(phase).as_ref().ok_or_else(refused)?;
        if !matches!(state.phase, Phase::Unsigned | Phase::Sealed) || state.literal_slot.is_none() {
            return Err(refused());
        }
        self.session
            .authenticate_original_ack_admit_cut(state.original.sequence, state.cut)?;
        Ok(PreparedOriginalCompleteRestoreTransfer {
            controller: self,
            phase,
        })
    }

    /// Borrows the actual settled phase pair under the same original emitter.
    ///
    /// # Errors
    /// Refuses an absent or unsettled phase, revoked emitter or missing raw reply.
    pub fn original_completed_complete_restore_transfer(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        phase: PacketCompleteRestoreTransferPhase,
    ) -> Result<CompletedOriginalCompleteRestoreTransfer<'_>, ProviderError> {
        emitter.authenticate_original(self)?;
        let state = self.transfer_slot(phase).as_ref().ok_or_else(refused)?;
        state.validate_owned_snapshot()?;
        Ok(CompletedOriginalCompleteRestoreTransfer {
            phase,
            original: &state.original,
            response: state.response.as_ref().ok_or_else(refused)?,
        })
    }

    /// Checks the actual fresh target across independent prepare/commit cuts.
    ///
    /// # Errors
    /// Refuses another registration, actor, installed codec or selected mechanism.
    pub fn authenticate_archived_protocol_transfer_mapping(
        &self,
        mapping: &PreparedArchivedProtocolMapping,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.session
            .authenticate_archived_protocol_transfer_mapping(mapping, &self.protocol_owner)
    }
}

impl PreparedOriginalCompleteRestoreTransfer<'_> {
    fn state(&self) -> Result<&AssignedOriginalCompleteRestore, ProviderError> {
        self.controller
            .transfer_slot(self.phase)
            .as_ref()
            .ok_or_else(refused)
    }
    /// Returns the distinct original phase.
    pub const fn phase(&self) -> PacketCompleteRestoreTransferPhase {
        self.phase
    }
    /// Borrows the full actual assigned request, including any stored proof.
    ///
    /// # Errors
    /// Refuses foreign origin, missing slot or an expired/changed operation cut.
    pub fn original(&self) -> Result<&Envelope, ProviderError> {
        self.controller.protocol_owner.ensure_current()?;
        let state = self.state()?;
        if state.phase != Phase::Complete {
            self.controller
                .session
                .authenticate_original_ack_admit_cut(state.original.sequence, state.cut)?;
        }
        Ok(&state.original)
    }
    /// Checks the same installed emitter and this original operation cut.
    ///
    /// # Errors
    /// Refuses foreign/revoked emitter, changed sequence or expired assigned cut.
    pub fn authenticate_original_emitter(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(), ProviderError> {
        emitter.authenticate_original(self.controller)?;
        self.original()?;
        Ok(())
    }
    /// Rechecks the actual original canonical restoration uploader association.
    ///
    /// # Errors
    /// Refuses a foreign/revoked uploader or changed assigned phase owner.
    pub fn authenticate_original_restore_input_emitter(
        &self,
        emitter: &OriginalCanonicalRestoreInputEmitter,
    ) -> Result<(), ProviderError> {
        emitter.authenticate_original(self.controller)?;
        self.original()?;
        Ok(())
    }

    /// Checks the same fresh mapping owner, registration, codec and nonce.
    ///
    /// # Errors
    /// Refuses another retained mapping or changed fresh target association.
    pub fn authenticate_archived_mapping(
        &self,
        mapping: &PreparedArchivedProtocolMapping,
    ) -> Result<(), ProviderError> {
        self.controller
            .authenticate_archived_protocol_transfer_mapping(mapping)?;
        let state = self.state()?;
        mapping.authenticate_identity(&state.mapping_identity)?;
        if state.nonce != *mapping.nonce() {
            return Err(refused());
        }
        Ok(())
    }
    /// Borrows digests from the same full original Hello journal and Connection.
    ///
    /// # Errors
    /// Refuses another actor/journal, revoked codec or incomplete original frames.
    pub fn original_canonical_ack_hello_frame_digests(
        &self,
        journal: &super::super::OriginalHelloJournal,
    ) -> Result<crate::native_hello::OriginalHelloFrameDigests, ProviderError> {
        self.controller
            .original_canonical_ack_hello_frame_digests(journal)
    }
    /// Seals the exact phase proof into its retained original and literal slot.
    ///
    /// # Errors
    /// Refuses a wrong-phase proof, second attempt, changed emitter/cut or credit.
    pub fn seal(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        proof: PacketCompleteRestoreTransferProof,
    ) -> Result<(), ProviderError> {
        self.authenticate_original_emitter(emitter)?;
        proof.validate_data(self.phase)?;
        let selected_fresh = self.phase == PacketCompleteRestoreTransferPhase::Prepare
            && self
                .state()?
                .original
                .extensions
                .contains_key(PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING);
        if selected_fresh {
            if self
                .controller
                .original_native5_fresh_restore_allocation_selection()?
                != Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
            {
                return Err(refused());
            }
            fresh_prepare::authenticate_unsigned_fresh_prepare(&self.state()?.original)?;
        }
        let slot = match self.phase {
            PacketCompleteRestoreTransferPhase::Prepare => {
                &mut self.controller.original_complete_restore_prepare
            }
            PacketCompleteRestoreTransferPhase::Commit => {
                &mut self.controller.original_complete_restore_commit
            }
        };
        let state = slot.as_mut().ok_or_else(refused)?;
        if state.phase != Phase::Unsigned
            || (!selected_fresh && state.original.extensions.len() != 1)
            || !state
                .original
                .extensions
                .contains_key(self.phase.request_extension())
        {
            return Err(refused());
        }
        state.phase = Phase::Sealing;
        let value =
            serde_json::to_value(proof).map_err(crucible_node_format::ContractError::from)?;
        state
            .original
            .extensions
            .insert(self.phase.proof_extension().into(), value);
        self.controller.session.seal_original_ack_admit(
            &mut self.controller.custody,
            &state.original,
            &mut state.bytes,
            state.literal_slot,
        )?;
        state.phase = Phase::Sealed;
        Ok(())
    }
    /// Publishes this exact sealed original and stores its raw reply first.
    ///
    /// # Errors
    /// Refuses repeated publication, an occupied result, stale original cut or
    /// transport/schema error. The original owners and sticky phase remain held.
    pub fn publish_into(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        completed: &mut Option<ResponseBody>,
    ) -> Result<(), ProviderError> {
        self.publish_into_with_prefix(emitter, completed, false)
    }

    /// Publishes the selected Fresh transfer with its closed held-proof prefix.
    ///
    /// Prepare receives no provider requests. Commit accepts one canonical held
    /// object in the native producer's exact Begin/chunk/Finish order. Its full
    /// terminal reference must match that object. This validates protocol shape;
    /// the Source still supplies the real claim, proof and keyed receipt checks.
    ///
    /// # Errors
    /// Refuses an unselected codec, reused publication, stale emitter/cut or a
    /// changed prefix. Partial raw frames, cache/content and phase remain held.
    pub fn publish_selected_into(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        completed: &mut Option<ResponseBody>,
    ) -> Result<(), ProviderError> {
        self.publish_into_with_prefix(emitter, completed, true)
    }

    fn publish_into_with_prefix(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        completed: &mut Option<ResponseBody>,
        selected: bool,
    ) -> Result<(), ProviderError> {
        self.authenticate_original_emitter(emitter)?;
        let mut prefix = if selected {
            if self.controller.original_native5_complete_restore_selection()?
                != Some(crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
                || self.controller.original_native5_fresh_restore_allocation_selection()?
                != Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
            {
                return Err(refused());
            }
            Some(
                super::super::session::restore_transfer_prefix::HeldPrefix::new(
                    self.phase,
                    self.controller.authority(),
                )?,
            )
        } else {
            None
        };
        if completed.is_some() {
            return Err(refused());
        }
        let slot = match self.phase {
            PacketCompleteRestoreTransferPhase::Prepare => {
                &mut self.controller.original_complete_restore_prepare
            }
            PacketCompleteRestoreTransferPhase::Commit => {
                &mut self.controller.original_complete_restore_commit
            }
        };
        let state = slot.as_mut().ok_or_else(refused)?;
        if state.phase != Phase::Sealed {
            return Err(refused());
        }
        state.phase = Phase::Publishing;
        let reply = if let Some(prefix) = prefix.as_mut() {
            self.controller
                .session
                .publish_original_complete_restore_transfer_with_prefix(
                    &mut self.controller.custody,
                    &state.original,
                    &state.bytes,
                    state.literal_slot,
                    state.cut,
                    prefix,
                )?
        } else {
            self.controller
                .session
                .publish_original_complete_restore_transfer(
                    &mut self.controller.custody,
                    &state.original,
                    &state.bytes,
                    state.literal_slot,
                    state.cut,
                )?
        };
        state.response = Some(reply);
        let response = state.response.as_ref().ok_or_else(refused)?;
        let projection =
            crate::connection::CompleteRestoreTransferProjection::from_envelope(response)?;
        if projection.phase() != self.phase
            || !matches!(
                projection,
                crate::connection::CompleteRestoreTransferProjection::Receipt { .. }
            )
        {
            return Err(refused());
        }
        let request = decode_request(state.original.method, &state.original.body)?;
        *completed = Some(decode_response(&request, &response.body)?);
        state.phase = Phase::Complete;
        Ok(())
    }
}

fn authenticate_mapping_reference(
    reference: &ContentRef,
    mapping: &PreparedArchivedProtocolMapping,
) -> Result<(), ProviderError> {
    let value = serde_json::to_value(mapping.normalization_view())
        .map_err(crucible_node_format::ContractError::from)?;
    let bytes = canonical::canonical_json(&value)?;
    reference.verify(&bytes)?;
    Ok(())
}
fn refused() -> ProviderError {
    ProviderError::Correlation("original restore transfer phase changed")
}
fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("original restore transfer bank credit")
}

/// Constructs the same assigned transfer header after the real issuer's guards.
///
/// This only moves/duplicates routing data. The caller retains all mapping,
/// emitter, original phase, sequence/cut and subsequent proof checks.
fn assigned_transfer_original(
    authority: &crate::handshake::ConnectionAuthority,
    route: &ControllerRoute,
    request_id: Id,
    sequence: U64,
    body: Map<String, Value>,
    extensions: Extensions,
) -> Envelope {
    Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(Some(authority.session_id().clone())),
        incarnation_id: Nullable(Some(authority.incarnation_id().clone())),
        node_id: Nullable(Some(route.node.clone())),
        execution_owner_id: Nullable(Some(route.execution_owner.clone())),
        capture_owner_id: Nullable(None),
        request_id: Nullable(Some(request_id)),
        operation_id: Nullable(None),
        sequence,
        method: Method::Begin,
        body,
        extensions,
    }
}

#[cfg(test)]
impl CnpController {
    /// Reuses the actual production header writer without issuing a phase owner.
    pub(crate) fn original_assigned_transfer_envelope_fixture_data(
        authority: &crate::handshake::ConnectionAuthority,
        route: &ControllerRoute,
        request_id: Id,
        sequence: U64,
        body: Map<String, Value>,
        extensions: Extensions,
    ) -> Envelope {
        assigned_transfer_original(authority, route, request_id, sequence, body, extensions)
    }
}
