//! Runs the real once Capture under its original token and admitted Source row.
//!
//! All private Source/SDK/native owners stay retained through refusals. The
//! controller advances only through the existing selected uploads, Capture and
//! confirmation; no model operation or synthetic checkpoint is introduced.

use super::super::*;
use super::{
    construction_data::OriginalSourceRestoredCaptureConstructionData as Row,
    logical::{
        OriginalSourceRestoredSettled17WriteInputs, OriginalSourceRestoredSettledSemantic17View,
    },
    owner::CaptureOnceOwner,
    quote_context::{
        OriginalSourceRestoredCaptureEncodingInputs as Encoding,
        OriginalSourceRestoredCaptureQuoteInputs as Quote,
    },
    sdk_effect::CaptureSdkOwners,
};
use crate::{
    node_adapters::cnp::semantic::{
        node::OriginalRestoredSettledNodeHistoryView,
        process::{FreshCurrentScratch, OriginalFreshQueryReadCall},
    },
    node_admission::{OriginalRestoredCaptureClaim, OriginalRestoredCaptureSigningInputs},
    node_contract::{OriginalLineageOwnerCaptureTicket, OriginalLineageRuntimeRecord},
};
use crucible_node_format::canonical;
use crucible_node_transport::{
    client::CnpController,
    protocol_snapshot::restored_journal17::PacketRestoredSettledAncestry17,
    reference_packet::service::{
        complete_restore::activation::PacketRestorationActivationScope,
        native_startup::original_restored_settled_capture_auxiliary_geometry_for_lengths_data,
        restored_settled_capture::{
            PacketRestoredSettledCaptureRequest, RESTORED_SETTLED_CAPTURE_REQUEST,
            upload::{
                PacketRestoredSettledCaptureUploadOrdinal,
                PacketRestoredSettledCaptureUploadRequest,
            },
        },
    },
};
use serde_json::Value;

pub(super) struct FrozenCheckpoint {
    pub(super) record: PacketNativeRestoredRecord,
    pub(super) underlying: PacketNative5UnderlyingRecord,
    pub(super) measurement: ContentRef,
    pub(super) first_observation: ContentRef,
    pub(super) scope: PacketRestorationActivationScope,
    pub(super) frontier: U64,
}

impl Clone for FrozenCheckpoint {
    fn clone(&self) -> Self {
        let Self {
            record,
            underlying,
            measurement,
            first_observation,
            scope,
            frontier,
        } = self;
        Self {
            record: clone_restored_record_data(record),
            underlying: clone_underlying_record_data(underlying),
            measurement: measurement.clone(),
            first_observation: first_observation.clone(),
            scope: scope.clone(),
            frontier: *frontier,
        }
    }
}

// These public DTOs are inert proof/model DATA, independently duplicable under
// the caller's admitted metadata row. No native owner or read permission moves.
pub(super) fn clone_restored_record_data(
    current: &PacketNativeRestoredRecord,
) -> PacketNativeRestoredRecord {
    let PacketNativeRestoredRecord {
        schema,
        native_receipt,
        captured_owner_state,
        captured_journal,
        mapping,
        restore_commit,
        restore_response,
        context_digest,
        physical_gate_held,
    } = current;
    PacketNativeRestoredRecord {
        schema: schema.clone(),
        native_receipt: native_receipt.clone(),
        captured_owner_state: captured_owner_state.clone(),
        captured_journal: captured_journal.clone(),
        mapping: mapping.clone(),
        restore_commit: restore_commit.clone(),
        restore_response: restore_response.clone(),
        context_digest: context_digest.clone(),
        physical_gate_held: *physical_gate_held,
    }
}

pub(super) fn clone_underlying_record_data(
    current: &PacketNative5UnderlyingRecord,
) -> PacketNative5UnderlyingRecord {
    match current {
        PacketNative5UnderlyingRecord::Producer(record) => {
            PacketNative5UnderlyingRecord::Producer(record.clone())
        }
        PacketNative5UnderlyingRecord::Reactive(record) => {
            PacketNative5UnderlyingRecord::Reactive(record.clone())
        }
    }
}

fn clone_ancestry_data(
    current: &crucible_node_transport::protocol_snapshot::restored_journal17::PacketRestoredSettledAncestry17,
) -> crucible_node_transport::protocol_snapshot::restored_journal17::PacketRestoredSettledAncestry17
{
    use crucible_node_transport::protocol_snapshot::restored_journal17::PacketRestoredSettledAncestry17;
    let PacketRestoredSettledAncestry17 {
        parent_archive_index,
        parent_manifest,
        first_semantic,
        first_journal,
        first_observation,
        restoration_commit,
        restoration_hold,
    } = current;
    PacketRestoredSettledAncestry17 {
        parent_archive_index: parent_archive_index.clone(),
        parent_manifest: parent_manifest.clone(),
        first_semantic: first_semantic.clone(),
        first_journal: first_journal.clone(),
        first_observation: first_observation.clone(),
        restoration_commit: restoration_commit.clone(),
        restoration_hold: restoration_hold.clone(),
    }
}

/// Owns all independently constructed Source arguments and exact final objects.
pub(super) struct CaptureConstructionOwners {
    pub(super) started: bool,
    pub(super) frozen: Option<FrozenCheckpoint>,
    pub(super) ancestry: Option<
        crucible_node_transport::protocol_snapshot::restored_journal17::PacketRestoredSettledAncestry17,
    >,
    pub(super) capture: Option<PacketRestoredSettledCaptureRequest>,
    pub(super) arguments: Option<Value>,
    pub(super) body: Option<BeginRequest>,
    pub(super) uploads: [Option<PacketRestoredSettledCaptureUploadRequest>; 2],
    pub(super) ids: [Option<Id>; 4],
    pub(super) finalization: super::finalization::FinalizationOwners,
    pub(super) final_started: bool,
    pub(super) final_value: Option<Value>,
    pub(super) final_bytes: Vec<u8>,
    pub(super) final_reference: Option<ContentRef>,
    pub(super) node_bytes: Vec<u8>,
    pub(super) node_reference: Option<ContentRef>,
}

impl CaptureConstructionOwners {
    pub(super) fn empty() -> Self {
        Self {
            started: false,
            frozen: None,
            ancestry: None,
            capture: None,
            arguments: None,
            body: None,
            uploads: [None, None],
            ids: [None, None, None, None],
            finalization: super::finalization::FinalizationOwners::empty(),
            final_started: false,
            final_value: None,
            final_bytes: Vec::new(),
            final_reference: None,
            node_bytes: Vec::new(),
            node_reference: None,
        }
    }

    pub(super) fn is_started_data(&self) -> bool {
        self.started
    }

    pub(super) fn retained_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::value_storage_with_error;
        use crucible_node_transport::{
            client::RestoredSettledCaptureTypedOwnerData,
            reference_packet::service::complete_restore::activation::restoration_activation_retained_native_evidence_data,
        };
        let Self {
            started: _,
            frozen,
            ancestry,
            capture,
            arguments,
            body,
            uploads,
            ids,
            finalization,
            final_started: _,
            final_value,
            final_bytes,
            final_reference,
            node_bytes,
            node_reference,
        } = self;
        let mut total = super::construction_quote::sum(
            &[
                final_bytes.capacity(),
                node_bytes.capacity(),
                finalization.retained_storage_data(maximum)?,
            ],
            maximum,
        )?;
        let mut add_facts =
            |facts: &crucible_node_transport::retained_metadata::RetainedProtocolMetadataFacts| {
                total = super::construction_quote::sum(
                    &[
                        total,
                        PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                            facts, maximum,
                        )?,
                    ],
                    maximum,
                )?;
                Ok::<(), RuntimeError>(())
            };
        if let Some(frozen) = frozen {
            add_facts(
                &restoration_activation_retained_native_evidence_data(
                    &frozen.record,
                    Some(&frozen.underlying),
                )
                .map_err(|_| RuntimeError::ResourceLimit)?,
            )?;
            add_facts(
                &frozen
                    .scope
                    .original_capture17_retained_metadata_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            )?;
        }
        for value in capture
            .iter()
            .map(RestoredSettledCaptureTypedOwnerData::CaptureRequest)
            .chain(
                uploads
                    .iter()
                    .flatten()
                    .map(RestoredSettledCaptureTypedOwnerData::UploadRequest),
            )
        {
            add_facts(
                &value
                    .retained_metadata_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            )?;
        }
        if let Some(body) = body {
            add_facts(
                &crucible_node_transport::reference_packet::service::native_startup::PacketRestoredProducerTypedOwnerData::Begin(body)
                    .retained_metadata_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            )?;
        }
        if let Some(ancestry) = ancestry {
            for reference in ancestry.references_data() {
                total = super::construction_quote::sum(
                    &[total, NodeRuntime::capture_reference_storage(reference)?],
                    maximum,
                )?;
            }
        }
        for value in arguments.iter().chain(final_value.iter()) {
            total = super::construction_quote::sum(
                &[
                    total,
                    value_storage_with_error::<RuntimeError>(value, 0, maximum)?,
                ],
                maximum,
            )?;
        }
        for id in ids.iter().flatten() {
            total = super::construction_quote::sum(&[total, id.allocated_capacity()], maximum)?;
        }
        for reference in final_reference.iter().chain(node_reference.iter()) {
            total = super::construction_quote::sum(
                &[total, NodeRuntime::capture_reference_storage(reference)?],
                maximum,
            )?;
        }
        if let Some(frozen) = frozen {
            for reference in [&frozen.measurement, &frozen.first_observation] {
                total = super::construction_quote::sum(
                    &[total, NodeRuntime::capture_reference_storage(reference)?],
                    maximum,
                )?;
            }
        }
        Ok(total)
    }
}

/// Borrows genuine Source completion and the exact retained encoded outputs.
///
/// This loan has no external constructor, decoder or authority conversion. The
/// Window independently checks the actual ticket, Runtime7 and row before it
/// accepts completion; the complete archive still owns joint persistence.
pub struct OriginalSourceRestoredCaptureCompletion<'a> {
    row: &'a Row,
    ancestry: &'a PacketRestoredSettledAncestry17,
    inherited: Option<&'a super::logical::OriginalSourceRestoredSettled17Read>,
    archive: &'a crate::node_state::CompleteOriginalRestorationSource,
    world: &'a WorldActivation,
    ticket: &'a OriginalLineageOwnerCaptureTicket<'a>,
    pub(super) record: &'a OriginalLineageRuntimeRecord,
    runtime: &'a crate::node_scheduling::InputPayload,
    semantic: (&'a ContentRef, &'a [u8]),
    history_prefix: (&'a ContentRef, &'a [u8]),
    node: (&'a ContentRef, &'a [u8]),
    native: &'a crucible_node_transport::protocol_snapshot::restored_settled17::ValidatedRestoredSettledNative17CaptureOutputs,
    sdk: crucible_node_transport::client::OriginalCompletedRestoredSettledCaptureData<'a>,
    finalization: &'a super::finalization::FinalizationOwners,
    materialization: &'a std::cell::RefCell<CaptureMaterializationOwner>,
}

impl OriginalSourceRestoredCaptureCompletion<'_> {
    /// Borrows the exact completed full semantic17 object.
    pub fn semantic_data(&self) -> (&ContentRef, &[u8]) {
        self.semantic
    }

    /// Borrows the actual uploaded prefix named by this final Journal17 cut.
    ///
    /// The tuple comes from the same completed Source Capture owner. Archive
    /// enrollment and all copied evidence remain independently funded.
    pub fn history_prefix_data(&self) -> (&ContentRef, &[u8]) {
        self.history_prefix
    }

    /// Borrows the exact canonical embedded Node object from that same encoding.
    pub fn node_data(&self) -> (&ContentRef, &[u8]) {
        self.node
    }

    /// Borrows the real native graph after full current-checkpoint validation.
    pub fn native_outputs_data(
        &self,
    ) -> &crucible_node_transport::protocol_snapshot::restored_settled17::ValidatedRestoredSettledNative17CaptureOutputs{
        self.native
    }

    /// Borrows the actual completed SDK originals and content banks.
    ///
    /// Archive copies remain independently funded by the owning archive caller.
    pub fn completed_sdk_data(
        &self,
    ) -> &crucible_node_transport::client::OriginalCompletedRestoredSettledCaptureData<'_> {
        &self.sdk
    }

    /// Borrows the same-supervisor post-confirmation Controller24 component.
    ///
    /// # Errors
    /// Refuses an incomplete retained finalizer; no historical data is promoted.
    pub(crate) fn host_protocol_data(&self) -> Result<(&ContentRef, &[u8]), RuntimeError> {
        self.finalization.controller_data()
    }

    /// Borrows the final Journal17 built from the actual four completed SDK pairs.
    ///
    /// # Errors
    /// Refuses an incomplete retained finalizer.
    pub(crate) fn journal_data(&self) -> Result<(&ContentRef, &[u8]), RuntimeError> {
        self.finalization.journal_data()
    }

    /// Borrows the original scope-proof body enrolled beside this capture.
    ///
    /// # Errors
    /// Refuses an incomplete retained finalizer or absent original proof.
    pub(crate) fn scope_proof_data(&self) -> Result<(&ContentRef, &[u8]), RuntimeError> {
        self.finalization.proof_data()
    }

    pub(crate) fn authenticate_claim_data(
        &self,
        row: &Row,
        world: &WorldActivation,
        ticket: &OriginalLineageOwnerCaptureTicket<'_>,
        record: &OriginalLineageRuntimeRecord,
        runtime: &crate::node_scheduling::InputPayload,
    ) -> Result<(), RuntimeError> {
        self.row.authenticate_same_construction_data(row)?;
        if !self.world.same_authority(world)
            || !std::ptr::eq(self.ticket, ticket)
            || !std::ptr::eq(self.record, record)
            || !std::ptr::eq(self.runtime, runtime)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

impl PacketCompleteSemanticSource {
    /// Performs one fully admitted Capture using this exact armed original read.
    ///
    /// The caller lends actual Node custody and immutable signed ancestry under
    /// its same live Window/supervisor and supplies counting banks admitted
    /// before quotation. The claim and consumed read token remain independent
    /// prerequisites; this method creates neither from stored Source history.
    ///
    /// # Errors
    /// Refuses a foreign row/read/claim, changed prefix extent, unsupported live
    /// family, any transport/native/current mismatch, output/callback failure or
    /// final sticky read refusal. All actual Source and SDK partials remain held.
    pub(in crate::node_adapters::cnp::semantic) fn run_original_restored_capture_source_data<R>(
        &self,
        controller: &mut CnpController,
        launch: &PacketNative5SourceLaunch,
        raw5: &[u8],
        inputs: &OriginalRestoredCaptureSigningInputs<'_>,
        claim: &OriginalRestoredCaptureClaim<'_>,
        node: &OriginalRestoredSettledNodeHistoryView<'_>,
        encoding: &Encoding<'_>,
        call: OriginalFreshQueryReadCall<'_>,
        scratch: &mut FreshCurrentScratch,
        inspect: impl FnOnce(&OriginalSourceRestoredCaptureCompletion<'_>) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        self.authenticate_unused_signed_observation17_owner_data()?;
        self.authenticate_unused_input17_owner_data()?;
        claim.authenticate_current_data(self, controller as *const _)?;
        claim.authenticate_inputs_data(inputs)?;
        inputs.authenticate_current_data()?;
        let row = *claim.row_data();
        if !std::ptr::eq(row.launch, launch)
            || row.launch_digest != *blake3::hash(raw5).as_bytes()
            || !std::ptr::eq(inputs.source, self)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.authenticate_original_restored_settled_source17_launch_data(launch, raw5)?;
        // Repeat the actual DATA count while the same read is armed, before
        // allocating a prefix DOM. A different Node/Source shape gains no credit.
        self.with_original_restored_capture_ancestry17_data(
            controller,
            inputs,
            |ancestry, inherited| {
                if !same_prior_data(inherited, encoding.inherited) {
                    return Err(RuntimeError::ForeignAuthority);
                }
                let quote = Quote {
                    ancestry,
                    inherited,
                    aliases: encoding.aliases,
                    records: encoding.records,
                    provider_aliases: encoding.provider_aliases,
                };
                self.with_latest_original_live_checkpoint17_cache_data(
                    controller,
                    inputs.world,
                    &call,
                    scratch,
                    |current| {
                        let counted = super::accounting::extent_data(
                            self,
                            controller,
                            launch,
                            inputs,
                            node,
                            &quote,
                            current.completed_frontier_data(),
                            row.checkpoint,
                            row.maximum,
                        )?;
                        if counted != row.prefix {
                            return Err(RuntimeError::ForeignAuthority);
                        }
                        let association = self
                            .ack_peer_association
                            .try_borrow()
                            .map_err(|_| RuntimeError::OwnerBusy)?;
                        let original =
                            association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
                        let mut owner = original
                            .restored_capture
                            .try_borrow_mut()
                            .map_err(|_| RuntimeError::OwnerBusy)?;
                        owner.freeze_current17_data(
                            current.record_data(),
                            current.underlying_data(),
                            current.measurement_data(),
                            current.first_observation_data(),
                            current.scope_data(),
                            current.completed_frontier_data(),
                        )?;
                        owner.construction.ancestry = Some(ancestry.to_owned_data()?);
                        Ok(())
                    },
                )
            },
        )?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let emitter = original
            .emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let native = original
            .native
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let birth = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let key = birth
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .original_fresh_query_key_data()?;
        // This owned, independently priced temporary avoids borrowing the
        // mutably held once owner's ancestry from its own prefix callback.
        let ancestry = {
            let owner = original
                .restored_capture
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            clone_ancestry_data(
                owner
                    .construction
                    .ancestry
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
            )
        };
        let mut recheck = || call.authenticate_original_source_read17_data(native, scratch);
        recheck()?;
        {
            let mut owner = original
                .restored_capture
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            encoding
                .aliases
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .begin_pass()?;
            owner.prepare_source_semantic17_prefix_data(
                &OriginalSourceRestoredSettled17WriteInputs {
                    source: self,
                    controller,
                    emitter,
                    world: inputs.world,
                    claim,
                    launch,
                    canonical_launch5: raw5,
                    key,
                    node,
                    ancestry: &ancestry,
                    inherited: encoding.inherited,
                    aliases: encoding.aliases,
                    records: encoding.records,
                    provider_aliases: encoding.provider_aliases,
                },
                row.checkpoint,
                row.prefix,
                &mut recheck,
            )?;
            owner.build_and_run_current17_data(
                self,
                controller,
                emitter,
                inputs,
                claim,
                launch,
                raw5,
                &row,
                key,
                &mut recheck,
            )?;
        }
        recheck()?;
        // Final Serialize borrows the actual Complete once owner. Drop its
        // mutable loan first; unlike the preencoder this needs no override.
        {
            let mut owner = original
                .restored_capture
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            if owner.construction.final_started {
                return Err(RuntimeError::OutstandingObligations);
            }
            owner.construction.final_started = true;
        }
        encoding
            .aliases
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .begin_pass()?;
        let write = OriginalSourceRestoredSettled17WriteInputs {
            source: self,
            controller,
            emitter,
            world: inputs.world,
            claim,
            launch,
            canonical_launch5: raw5,
            key,
            node,
            ancestry: &ancestry,
            inherited: encoding.inherited,
            aliases: encoding.aliases,
            records: encoding.records,
            provider_aliases: encoding.provider_aliases,
        };
        let value = serde_json::to_value(self.borrowed_completed_semantic17_data(&write)?)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        {
            let mut owner = original
                .restored_capture
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            owner.retain_final_semantic17_data(value, row.semantic)?;
        }
        recheck()?;
        // The final Controller is later than the Source prefix and has its own
        // baseline-plus-SDK-growth row. Borrow the actual retained supervisor
        // from this Node; a reconstructed or absent witness cannot serialize it.
        {
            use crucible_node_transport::protocol_snapshot::restored_journal17::{
                PacketRestoredSettledHistoryCut17, PacketRestoredSettledJournal17Objects,
            };
            let sdk = controller
                .original_completed_restored_settled_capture_data(emitter)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            let mut owner = original
                .restored_capture
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let before = {
                let native = owner.current_native_outputs17_data()?;
                canonical::content_ref(
                    native
                        .before_protocol_bytes_data()
                        .map_err(|_| RuntimeError::InvalidReceipt)?,
                    "application/json",
                )
                .map_err(|_| RuntimeError::InvalidReceipt)?
            };
            let state = &mut owner.construction;
            state.finalization.encode_controller_data(
                &node.original_controller_history_data(controller)?,
                inputs.scope_proof,
                inputs.scope_proof_body,
                &row.finalization,
                row.maximum,
            )?;
            let controller_reference = state.finalization.controller_data()?.0.clone();
            let receipt = sdk.receipt_data();
            state.finalization.objects = Some(PacketRestoredSettledJournal17Objects {
                snapshot: receipt.capture.native_snapshot_ref.clone(),
                before,
                control: receipt.capture.native_control_ref.clone(),
                anchor: receipt.capture.native_anchor_ref.clone(),
                after: receipt.native_after_ref.clone(),
                host_protocol: controller_reference,
                semantic: state
                    .final_reference
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .clone(),
                runtime_object: claim.runtime_object_data().reference.clone(),
                coordinator_checkpoint: claim.coordinator_checkpoint_data()?.0.clone(),
            });
            state.finalization.history_cut = Some(PacketRestoredSettledHistoryCut17 {
                prefix: sdk.request_data().history_prefix.clone(),
                next_sequence: sdk
                    .prefix_frontier_data()
                    .map_err(|_| RuntimeError::InvalidReceipt)?,
            });
            state
                .finalization
                .objects
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .validate_data()
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            state.finalization.encode_journal_data(
                state
                    .ancestry
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
                &sdk,
                &row.finalization,
                row.maximum,
            )?;
            state.retained_storage_data(row.maximum)?;
        }
        recheck()?;
        let result = {
            let owner = original
                .restored_capture
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            owner.current_bridge_data()?.authenticate_current_data(
                self,
                controller,
                emitter,
                inputs.world,
                key,
            )?;
            let state = &owner.construction;
            let completion = OriginalSourceRestoredCaptureCompletion {
                row: &row,
                ancestry: state
                    .ancestry
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
                inherited: encoding.inherited,
                archive: inputs.archive,
                finalization: &state.finalization,
                materialization: &owner.materialization,
                world: inputs.world,
                ticket: claim.ticket_data(),
                record: claim.runtime_record_data(),
                runtime: claim.runtime_object_data(),
                history_prefix: owner.completed_prefix_payload17_data()?,
                semantic: (
                    state
                        .final_reference
                        .as_ref()
                        .ok_or(RuntimeError::OwnerUnavailable)?,
                    &state.final_bytes,
                ),
                node: (
                    state
                        .node_reference
                        .as_ref()
                        .ok_or(RuntimeError::OwnerUnavailable)?,
                    &state.node_bytes,
                ),
                native: owner.current_native_outputs17_data()?,
                sdk: controller
                    .original_completed_restored_settled_capture_data(emitter)
                    .map_err(|_| RuntimeError::InvalidReceipt)?,
            };
            claim.retain_source_completion_data(&completion)?;
            inspect(&completion)
        };
        // Both successful and refused output callbacks repeat the live native
        // read. On any failure the consumed token's drop revokes its real owner.
        recheck()?;
        let result = result?;
        drop(recheck);
        call.complete(scratch, || {
            claim.authenticate_terminal_member_data(self, controller)?;
            let owner = original
                .restored_capture
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            owner.current_bridge_data()?.authenticate_current_data(
                self,
                controller,
                emitter,
                inputs.world,
                key,
            )
        })?;
        claim.complete_source_data(self, controller)?;
        Ok(result)
    }
}

pub(super) fn counter_scratch_data() -> usize {
    use std::{
        cell::{Ref, RefMut},
        mem::size_of,
    };
    size_of::<CaptureConstructionOwners>()
        + size_of::<FrozenCheckpoint>()
        + size_of::<OriginalSourceRestoredCaptureCompletion<'static>>()
        + size_of::<OriginalSourceRestoredSettled17WriteInputs<'static, 'static>>()
        + size_of::<OriginalSourceRestoredSettledSemantic17View<'static, 'static, 'static>>()
        + size_of::<Ref<'static, CaptureOnceOwner>>()
        + size_of::<RefMut<'static, CaptureOnceOwner>>()
        + size_of::<OriginalFreshQueryReadCall<'static>>()
        + size_of::<&mut FreshCurrentScratch>()
        + CnpSemanticSourceRead::original_fresh_query_call_scratch_data()
        + CnpSemanticSourceRead::original_fresh_query_armed_recheck_counter_scratch_data()
        + size_of::<Option<FrozenCheckpoint>>()
        + size_of::<[Option<Id>; 4]>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<Result<Value, serde_json::Error>>()
        + size_of::<Result<Vec<u8>, crucible_node_format::ContractError>>()
        + CaptureMaterializationOwner::counter_scratch_data()
}

#[path = "effect/materialization.rs"]
mod materialization;
pub(super) use materialization::{CaptureBornStorage, CaptureMaterializationOwner};

fn same_prior_data(
    a: Option<&super::logical::OriginalSourceRestoredSettled17Read>,
    b: Option<&super::logical::OriginalSourceRestoredSettled17Read>,
) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => std::ptr::eq(a, b),
        _ => false,
    }
}
