//! Quotes the independent Source signing graph before any transaction claim.
//!
//! These closed projections borrow actual originals. The row includes the
//! separately retained two-phase banks, normalized history, typed construction,
//! canonical/index/mapping work, SDK assignment and full raw receive/error
//! geometry. It is DATA: only the opaque installed window can authorize effects.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::sum_with_error;
use crate::node_contract::NodeRuntime;
use crucible_node_transport::reference_packet::service::fresh_restore_allocation::{
    FRESH_RESTORE_ALLOCATION_ALGORITHM, PACKET_FRESH_RESTORE_ALLOCATION_PROOF,
    PacketNativeFreshRestoreAllocationProof,
};
use std::io::Write;

#[path = "construction/projection.rs"]
mod projection;
use projection::*;

pub(crate) struct OriginalSourceRestoreSignerConstructionData {
    process: u32,
    thread: std::thread::ThreadId,
    source: *const PacketCompleteSemanticSource,
    controller: *const CnpController,
    identity: blake3::Hash,
    mapping_identity: blake3::Hash,
    requested: usize,
    scratch: usize,
    maximum: usize,
    mapping: usize,
    frame: usize,
    mapping_normalization: usize,
    maximum_record_bytes: usize,
    minimum_other_retained: usize,
}

impl OriginalSourceRestoreSignerConstructionData {
    pub(crate) fn requested_peak_bytes_data(&self) -> usize {
        self.requested
    }

    pub(crate) fn counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }

    pub(crate) fn mapping_normalization_requested_bytes_data(&self) -> usize {
        self.mapping_normalization
    }

    pub(super) fn maximum_requested_bytes_data(&self) -> usize {
        self.maximum
    }

    pub(super) fn maximum_mapping_bytes_data(&self) -> usize {
        self.mapping
    }

    pub(super) fn maximum_frame_bytes_data(&self) -> usize {
        self.frame
    }

    pub(super) fn authenticate_original_effect_data(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
        inputs: &OriginalRestorationSigningInputs<'_>,
    ) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        source.storage_origin_with_error::<RuntimeError>()?;
        if !std::ptr::eq(self.source, source)
            || !std::ptr::eq(self.controller, controller)
            || self.requested > self.maximum
            || self.maximum_record_bytes != inputs.maximum_record_bytes
            || inputs.observed_other_retained_bytes < self.minimum_other_retained
            || usize::try_from(controller.authority().limits().frame_bytes.get())
                .map_err(|_| RuntimeError::ResourceLimit)?
                != self.frame
            || fingerprint(
                source,
                inputs.archive,
                inputs.ticket,
                inputs.activation,
                inputs.journal,
                inputs.journal_reference,
                inputs.capture_terminal,
                inputs.native_allocation,
                inputs.prepare_id,
                inputs.commit_id,
            )? != self.identity
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

impl PacketCompleteSemanticSource {
    pub(crate) fn original_restoration_signer_construction_counter_scratch_data() -> usize {
        let fixed = size_of::<OriginalSourceRestoreSignerConstructionData>()
            + size_of::<OriginalRestorationSigningConstructionInputs<'static>>()
            + size_of::<OriginalRestorationSigningInputs<'static>>()
            + size_of::<OriginalRestorationTransactionClaim<'static>>()
            + size_of::<OriginalRestorationTransactionInspection<'static>>()
            + size_of::<OriginalRestorationMappingInputs<'static>>()
            + size_of::<OriginalSourceRestoreVerifiedPhase<'static>>()
            + size_of::<Result<OriginalSourceRestoreSignerConstructionData, RuntimeError>>()
            + size_of::<Result<OriginalSourceRestoreVerifiedPhase<'static>, RuntimeError>>()
            + size_of::<Result<
                std::cell::Ref<'static, Option<OriginalAckPeerAssociation>>,
                std::cell::BorrowError,
            >>()
            + size_of::<Result<
                std::cell::RefMut<'static, Option<OriginalAckPeerAssociation>>,
                std::cell::BorrowMutError,
            >>()
            + size_of::<Result<
                std::cell::Ref<'static, Option<OriginalAckPeerBirth>>,
                std::cell::BorrowError,
            >>()
            + size_of::<super::owner::OriginalSourceRestoreTransferAttempt>()
            + super::owner::phase_counter_scratch_data()
            + size_of::<std::cell::Ref<'static, Option<OriginalAckPeerAssociation>>>()
            + size_of::<std::cell::RefMut<'static, Option<OriginalAckPeerAssociation>>>()
            + size_of::<std::cell::Ref<'static, Option<OriginalAckPeerBirth>>>()
            + NodeRuntime::capture_serialization_counter_scratch_data()
            + CnpSemanticSourceRead::original_fresh_query_call_scratch_data()
            + CnpController::original_fresh_restore_prepare_binding_counter_scratch_data()
            + CnpController::original_complete_restore_input_inspection_counter_scratch_data()
            + CnpController::original_restore_transfer_source_projection_counter_scratch_data()
            + CnpController::original_selected_restore_held_prefix_counter_scratch_data()
            + CnpController::original_selected_restore_assignment_counter_scratch_data()
            + crucible_node_transport::retained_metadata::
                original_complete_restore_transfer_response_counter_scratch_data()
            + crucible_node_transport::client::original_host_source_json_counter_scratch_data()
            + crate::node_state::NativeArchiveRecord::original_restoration_index_counter_scratch_data()
            + projection_scratch_data()

            + size_of::<blake3::Hasher>() + size_of::<HashWriter>()
            + size_of::<[u8; 32]>() + size_of::<[u8; 8]>()
            + size_of::<Result<(), RuntimeError>>() + size_of::<Result<usize, RuntimeError>>()
            + size_of::<[usize; 32]>()
            // Both fixed term lists are copied into the checked array helper.
            // Retain their complete array and consumed iterator views explicitly.
            + size_of::<[usize; 3]>()
            + size_of::<std::array::IntoIter<usize, 3>>()
            + size_of::<[usize; 22]>()
            + size_of::<std::array::IntoIter<usize, 22>>()
            // Real custom scalar formatting is bounded before any visitor.
            // Base64's32 input bytes reserve44 encoded bytes, not initialized43.
            + 20 + 44;
        fixed.saturating_add(
            match Self::original_fresh_query_invocation_counter_scratch_data() {
                Ok(bytes) => bytes,
                Err(_) => usize::MAX,
            },
        )
    }

    pub(crate) fn original_restoration_signer_construction_data(
        &self,
        inputs: &OriginalRestorationSigningConstructionInputs<'_>,
        maximum: usize,
    ) -> Result<OriginalSourceRestoreSignerConstructionData, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let scratch = Self::original_restoration_signer_construction_counter_scratch_data();
        if scratch > maximum
            || !std::ptr::eq(self, inputs.source.as_ref())
            || inputs.prepare_id == inputs.commit_id
            || inputs.maximum_mapping_bytes != super::super::complete_restore::MAPPING_BYTES
        {
            return Err(RuntimeError::ResourceLimit);
        }
        self.authenticate_transfer_selection_data()?;
        inputs.ticket.authenticate_source(inputs.archive)?;
        let owner = inputs.ticket.owner()?;
        let target = inputs
            .activation
            .owners
            .iter()
            .find(|one| one.owner == owner.owner)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let native = inputs.ticket.native_restoration_construction_data()?;
        if native.selected_owner_construction_data().is_none() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        native.authenticate_original_references_data([
            &inputs.journal.native_after_protocol,
            &inputs.journal.native_control,
            &inputs.journal.native_anchor,
            &owner.state,
            inputs.journal_reference,
        ])?;
        if target.owner != self.installation().owner.owner.id
            || target.generation != self.installation().binding.authority.owner_generation
            || inputs.activation.world_binding_hash != self.installation().world_binding_hash
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let association = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        association.authenticate_transfer_ready_data()?;
        let emitter = association
            .emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        association
            .restore_input_emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .authenticate_original(inputs.controller)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        inputs
            .query
            .authenticate_original_source_context_data(
                inputs.controller,
                emitter,
                &self.installation().owner,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let report = inputs
            .query
            .report_data()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let frame = usize::try_from(inputs.controller.authority().limits().frame_bytes.get())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let transfer = association
            .restore_transfer_banks
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if transfer.signer.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        let current = association
            .native
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let mapping_view = inputs
            .controller
            .original_selected_archived_mapping_normalization_projection_data(
                &inputs.journal.host_protocol,
                &inputs.journal.native_after_protocol,
            )
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let mapping_normalization =
            NodeRuntime::original_runtime_constructor_serialization_storage_data(
                &mapping_view,
                maximum,
            )?;
        let index = inputs
            .archive
            .archive()
            .original_restoration_index_construction_storage_data(maximum)?
            .requested_bytes();
        let restoration = Restoration {
            schema: PACKET_COMPLETE_RESTORE_FEATURE,
            archive_index: Reference::future(
                "application/vnd.crucible.native-signed-index-body.v3+json",
            ),
            capture_manifest: inputs.archive.archive().artifact().into(),
            owner_state: (&owner.state).into(),
            journal: inputs.journal_reference.into(),
            source_runtime: (&inputs.journal.runtime).into(),
            backend_implementation: (&inputs.journal.backend_implementation).into(),
            backend_schema: (&owner.key.schema).into(),
            archived_cut: projection::Position::ceiling(),
            archived_ordinal: NUMBER,
            target_world: (&inputs.activation.world_binding_hash).into(),
            target_owner: &target.owner,
            target_owner_binding: (&report.data.scope.owner_binding).into(),
            target_activation: &inputs.activation.activation_id,
            target_generation: NUMBER,
            target_owner_generation: NUMBER,
            mapping: Reference::future("application/json"),
            nonce: DIGEST,
        };
        let prepare = Prepare {
            schema: PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION,
            restoration,
            host_protocol: (&inputs.journal.host_protocol).into(),
            native_protocol: (&inputs.journal.native_after_protocol).into(),
            native_control: (&inputs.journal.native_control).into(),
            native_anchor: (&inputs.journal.native_anchor).into(),
            transaction_id: inputs.prepare_id,
            generation: NUMBER,
            allocation: Allocation::ceiling(),
        };
        let commit = Commit {
            schema: PACKET_COMPLETE_RESTORE_COMMIT_EXTENSION,
            prepare: &prepare,
            capture_terminal: inputs.capture_terminal.into(),
            prepare_request_id: inputs.prepare_id,
            prepare_request_sequence: NUMBER,
            prepare_request_digest: DIGEST,
            prepare_response_sequence: NUMBER,
            prepare_response_digest: DIGEST,
            transfer_token: DIGEST,
        };
        let prepare_baseline = Baseline::for_restoration(inputs.prepare_id, &prepare.restoration);
        // The assigned Commit ID is distinct; both baselines retain the same
        // Source transaction ID carried in the original Prepare extension.
        let commit_baseline = Baseline::for_restoration(inputs.prepare_id, &prepare.restoration);

        let prepare_frame = AssignedEnvelope::new(
            inputs.controller,
            inputs.prepare_id,
            &prepare_baseline,
            PrepareExtensions {
                prepare: &prepare,
                binding: Binding {
                    schema: crucible_node_transport::reference_packet::service::
                        fresh_restore_allocation::PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING,
                    assigned_query: DIGEST,
                    completed_query_response: DIGEST,
                    allocation: inputs.query.allocation_reference_data()
                        .ok_or(RuntimeError::OwnerUnavailable)?.into()
                },
                proof: Proof::new(PACKET_COMPLETE_RESTORE_PREPARE_PROOF_EXTENSION)
            }
        );
        let commit_frame = AssignedEnvelope::new(
            inputs.controller,
            inputs.commit_id,
            &commit_baseline,
            CommitExtensions {
                commit: &commit,
                proof: Proof::new(PACKET_COMPLETE_RESTORE_COMMIT_PROOF_EXTENSION),
            },
        );
        let prepare_context = PrepareContext::ceiling();
        let commit_context = CommitContext::ceiling();
        let prepare_proof = Proof::new(PACKET_COMPLETE_RESTORE_PREPARE_PROOF_EXTENSION);
        let commit_proof = Proof::new(PACKET_COMPLETE_RESTORE_COMMIT_PROOF_EXTENSION);
        let prepare_receipt = PrepareReceipt::ceiling();
        let commit_receipt = CommitReceipt::ceiling();

        let shapes = ConstructionShapes {
            restoration: Shape::measure(&prepare.restoration, maximum)?,
            archive_binding: Shape::measure(&prepare.restoration.archive_binding(), maximum)?,
            target_binding: Shape::measure(&prepare.restoration.target_binding(), maximum)?,
            input_roster: Shape::measure(&prepare.input_roster(), maximum)?,
            prepare: Shape::measure(&prepare, maximum)?,
            commit: Shape::measure(&commit, maximum)?,
            prepare_baseline: Shape::measure(&prepare_baseline, maximum)?,
            commit_baseline: Shape::measure(&commit_baseline, maximum)?,
            prepare_frame: Shape::measure(&prepare_frame, maximum)?,
            commit_frame: Shape::measure(&commit_frame, maximum)?,
            prepare_identity: Shape::measure(&prepare_frame.identity(), maximum)?,
            commit_identity: Shape::measure(&commit_frame.identity(), maximum)?,
            prepare_context: Shape::measure(&prepare_context, maximum)?,
            commit_context: Shape::measure(&commit_context, maximum)?,
            prepare_proof: Shape::measure(&prepare_proof, maximum)?,
            commit_proof: Shape::measure(&commit_proof, maximum)?,
            prepare_receipt: Shape::measure(&prepare_receipt, maximum)?,
            commit_receipt: Shape::measure(&commit_receipt, maximum)?,
            held: Shape::measure(
                &Held::ceiling(
                    &prepare.restoration,
                    (&inputs.journal.native_control).into(),
                ),
                maximum,
            )?,
        };
        let raw = inputs
            .controller
            .original_complete_restore_transfer_raw_receive_storage_data()
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let binding = add(
            &[
                inputs.binding_quote.retained_growth_bytes(),
                inputs.binding_quote.maximum_simultaneous_transient_bytes(),
                inputs.binding_quote.declared_counter_scratch_bytes(),
            ],
            maximum,
        )?;
        let report_work = NodeRuntime::original_runtime_constructor_serialization_storage_data(
            &report.data,
            maximum,
        )?;
        let held_prefix = inputs
            .controller
            .original_selected_restore_held_prefix_storage_data()
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let assignment = inputs
            .controller
            .original_selected_restore_assignment_storage_data()
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let requested = add(
            &[
                scratch,
                transfer.allocated_bytes_with_error::<RuntimeError>()?,
                current.original_fresh_current_storage_data()?,
                index,
                mapping_normalization,
                mapping_normalization,
                binding,
                raw,
                raw,
                report_work,
                // The verified report proof is independently created from real
                // report DATA; its two digest banks coexist with the original.
                size_of::<PacketNativeFreshRestoreAllocationProof>(),
                PACKET_FRESH_RESTORE_ALLOCATION_PROOF.len(),
                FRESH_RESTORE_ALLOCATION_ALGORITHM.len(),
                32,
                32,
                held_prefix.0,
                held_prefix.1,
                held_prefix.2,
                assignment.0,
                assignment.1,
                assignment.2,
                shapes.requested_bytes(maximum)?,
            ],
            maximum,
        )?;
        inputs
            .query
            .authenticate_current(inputs.controller, emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let identity = fingerprint(
            self,
            inputs.archive,
            inputs.ticket,
            inputs.activation,
            inputs.journal,
            inputs.journal_reference,
            inputs.capture_terminal,
            inputs.native_allocation,
            inputs.prepare_id,
            inputs.commit_id,
        )?;
        Ok(OriginalSourceRestoreSignerConstructionData {
            process: std::process::id(),
            thread: std::thread::current().id(),
            source: self,
            controller: inputs.controller,
            identity,
            mapping_identity: mapping_identity(
                &inputs.journal.host_protocol,
                &inputs.journal.native_after_protocol,
            )?,
            requested,
            scratch,
            maximum,
            mapping: inputs.maximum_mapping_bytes,
            frame,
            mapping_normalization,
            maximum_record_bytes: inputs.maximum_record_bytes,
            minimum_other_retained: inputs.observed_other_retained_bytes,
        })
    }
}

fn add<const N: usize>(terms: &[usize; N], maximum: usize) -> Result<usize, RuntimeError> {
    sum_with_error::<RuntimeError, N>(*terms, maximum)
}

struct HashWriter(blake3::Hasher);
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn fingerprint(
    source: &PacketCompleteSemanticSource,
    archive: &crate::node_state::CompleteOriginalRestorationSource,
    ticket: &crate::node_state::CompleteOriginalNativeTicket,
    activation: &crate::node_contract::ActivationRecord,
    journal: &crate::node_adapters::cnp::PacketCompleteSettledJournal,
    journal_reference: &ContentRef,
    capture: &Envelope,
    allocation: &PacketCompleteRestoreInputAllocation,
    prepare: &Id,
    commit: &Id,
) -> Result<blake3::Hash, RuntimeError> {
    let mut writer = HashWriter(blake3::Hasher::new());
    let owner = ticket.owner()?;
    let native = ticket.native_restoration_construction_data()?;
    native.authenticate_original_references_data([
        &journal.native_after_protocol,
        &journal.native_control,
        &journal.native_anchor,
        &owner.state,
        journal_reference,
    ])?;
    // Actual scalar values, full references and actual terminal remain bound;
    // the quote's deliberately widened numeric projection is never authority.
    for value in [
        capture.sequence.get(),
        activation.generation.get(),
        journal.ordinal.get(),
    ] {
        writer.0.update(&value.to_be_bytes());
    }
    serde_json::to_writer(
        &mut writer,
        &(
            &source.installation().owner,
            archive.archive().artifact(),
            &owner.owner,
            &owner.state,
            &owner.key.schema,
            (
                &activation.activation_id,
                &activation.world_binding_hash,
                &activation.owners,
                activation.boundary,
                activation.generation,
            ),
            &journal.native_after_protocol,
            &journal.native_control,
            &journal.native_anchor,
            &journal.host_protocol,
            journal_reference,
            ActualEnvelope::from(capture),
            allocation,
            prepare,
            commit,
        ),
    )
    .map_err(|_| RuntimeError::InvalidReceipt)?;
    Ok(writer.0.finalize())
}

#[path = "construction/shapes.rs"]
mod shapes;
use shapes::{ConstructionShapes, Shape, projection_scratch_data};

fn mapping_identity(host: &ContentRef, native: &ContentRef) -> Result<blake3::Hash, RuntimeError> {
    let mut writer = HashWriter(blake3::Hasher::new());
    serde_json::to_writer(&mut writer, &(host, native))
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    Ok(writer.0.finalize())
}

impl OriginalSourceRestoreSignerConstructionData {
    pub(super) fn authenticate_original_mapping_data(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
        inputs: &OriginalRestorationMappingInputs<'_>,
    ) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        source.storage_origin_with_error::<RuntimeError>()?;
        if !std::ptr::eq(self.source, source)
            || !std::ptr::eq(self.controller, controller)
            || !std::ptr::eq(source, inputs.source.as_ref())
            || self.mapping_identity
                != mapping_identity(inputs.host_reference, inputs.native_reference)?
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}
