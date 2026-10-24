//! Derives selected transfer DTOs only from the actual admitted Source originals.
//!
//! The caller owns the real Core phase claim and prepays construction before
//! entering these helpers. These requests are data; neither their fields nor
//! a completed Commit can create a final four-owner restoration context.

use super::*;

impl PacketCompleteSemanticSource {
    pub(in super::super) fn authenticate_transfer_selection_data(
        &self,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;

        if self.complete_restore_selection.flatten()
            != Some(
                crucible_node_transport::reference_packet::service::complete_restore::
                    PacketNative5CompleteRestoreSelection::SourceSignedTransfer12
            )
            || self.restore_input_emitter_selection.flatten()
                != Some(
                    crucible_node_transport::reference_packet::service::complete_restore::
                        PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12
                )
            || self.fresh_restore_allocation_selection.flatten()
                != Some(
                    crucible_node_transport::reference_packet::service::fresh_restore_allocation::
                        PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13
                )
        {
            return Err(RuntimeError::UnsupportedFacet);
        }

        self.authenticate_original_fresh_query_invocation_data()
    }

    pub(super) fn authenticate_transfer_inputs_data(
        &self,
        inputs: &OriginalRestorationSigningInputs<'_>,
    ) -> Result<(), RuntimeError> {
        self.authenticate_transfer_selection_data()?;
        if !std::ptr::eq(self, inputs.source.as_ref()) || inputs.prepare_id == inputs.commit_id {
            return Err(RuntimeError::ForeignAuthority);
        }
        inputs.ticket.authenticate_source(inputs.archive)?;
        let owner = inputs.ticket.owner()?;
        let installed = self.installation();
        let target = inputs
            .activation
            .owners
            .iter()
            .find(|one| one.owner == owner.owner)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if owner.owner != installed.owner.owner.id
            || owner.participants != installed.owner.owner.participant_ids
            || inputs.activation.world_binding_hash != installed.world_binding_hash
            || target.generation != installed.binding.authority.owner_generation
            || owner.key.implementation != installed.provider.implementation.implementation_id
            || owner.key.profile.as_str() != "source-owned.packet-complete-original-lineage/5"
            || !matches!(
                owner.key.schema.id.as_str(),
                "source-owned.packet-native-continuation/13"
                    | "source-owned.packet-native-continuation/14"
            )
            || !installed
                .provider
                .implementation
                .formats
                .contains(&owner.key.schema)
            || !installed
                .binding
                .compatibility
                .implementation
                .formats
                .contains(&owner.key.schema)
            || owner.state != inputs.journal.native_snapshot
            || owner.cut != inputs.journal.cut
            || !owner.evidence.contains(inputs.journal_reference)
            || inputs.mapping.archive_protocol() != &inputs.journal.host_protocol
            || inputs.mapping.native_protocol() != &inputs.journal.native_after_protocol
        {
            return Err(RuntimeError::ForeignAuthority);
        }
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
        inputs
            .native_allocation
            .validate_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        Ok(())
    }

    pub(super) fn derive_transfer_prepare_request(
        &self,
        inputs: &OriginalRestorationSigningInputs<'_>,
        target_owner_binding: &HashRef,
        mapping_reference: ContentRef,
        nonce: &[u8; 32],
        generation: U64,
    ) -> Result<PacketCompleteRestorePrepareRequest, RuntimeError> {
        self.authenticate_transfer_inputs_data(inputs)?;
        if inputs.mapping.nonce() != nonce {
            return Err(RuntimeError::ForeignAuthority);
        }
        let owner = inputs.ticket.owner()?;
        let target = inputs
            .activation
            .owners
            .iter()
            .find(|one| one.owner == owner.owner)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let index = inputs
            .archive
            .archive()
            .complete_original_index_identity(
                inputs.maximum_record_bytes,
                inputs.observed_other_retained_bytes,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let restoration = PacketCompleteRestoreRequest {
            schema: PACKET_COMPLETE_RESTORE_FEATURE.to_owned(),
            archive_index: index,
            capture_manifest: inputs.archive.archive().artifact().clone(),
            owner_state: owner.state.clone(),
            journal: inputs.journal_reference.clone(),
            source_runtime: inputs.journal.runtime.clone(),
            backend_implementation: inputs.journal.backend_implementation.clone(),
            backend_schema: owner.key.schema.clone(),
            archived_cut: inputs.journal.cut,
            archived_ordinal: inputs.journal.ordinal,
            target_world: inputs.activation.world_binding_hash.clone(),
            target_owner: target.owner.clone(),
            target_owner_binding: target_owner_binding.clone(),
            target_activation: inputs.activation.activation_id.clone(),
            target_generation: inputs.activation.generation,
            target_owner_generation: target.generation,
            mapping: mapping_reference,
            nonce: Bytes::new(nonce.to_vec()),
        };
        Ok(PacketCompleteRestorePrepareRequest {
            schema: PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION.to_owned(),
            restoration,
            host_protocol: inputs.journal.host_protocol.clone(),
            native_protocol: inputs.journal.native_after_protocol.clone(),
            native_control: inputs.journal.native_control.clone(),
            native_anchor: inputs.journal.native_anchor.clone(),
            transaction_id: inputs.prepare_id.clone(),
            generation,
            allocation: copy_allocation(inputs.native_allocation),
        })
    }
}

pub(super) fn baseline(
    id: &Id,
    request: &PacketCompleteRestoreRequest,
) -> Result<BeginRequest, RuntimeError> {
    let arguments = PrepareRestoreArguments {
        transaction_id: id.clone(),
        capture_manifest: request.capture_manifest.clone(),
        expected_world_binding_hash: request.target_world.clone(),
        expected_owner_binding_hash: request.target_owner_binding.clone(),
        destination_owner_ids: vec![request.target_owner.clone()],
    };
    let serde_json::Value::Object(arguments) =
        serde_json::to_value(arguments).map_err(|_| RuntimeError::InvalidReceipt)?
    else {
        return Err(RuntimeError::InvalidReceipt);
    };
    Ok(BeginRequest {
        kind: BeginKind::PrepareRestore,
        binding_hash: request.target_owner_binding.clone(),
        owner_generation: request.target_owner_generation,
        activation_id: Nullable(Some(request.target_activation.clone())),
        world_generation: request.target_generation,
        arguments,
        extensions: Default::default(),
    })
}

fn copy_allocation(
    value: &PacketCompleteRestoreInputAllocation,
) -> PacketCompleteRestoreInputAllocation {
    let PacketCompleteRestoreInputAllocation {
        maximum_known_requested_bytes,
        maximum_input_bytes,
        maximum_nodes,
        maximum_depth,
        maximum_owned_backing_bytes,
        maximum_tree_entries,
        maximum_metadata_rows,
        maximum_literal_backing_bytes,
        maximum_content_transfers,
        maximum_content_objects,
        maximum_content_groups,
        maximum_content_bytes,
        maximum_content_metadata_bytes,
        maximum_model_bytes,
    } = value;
    PacketCompleteRestoreInputAllocation {
        maximum_known_requested_bytes: *maximum_known_requested_bytes,
        maximum_input_bytes: *maximum_input_bytes,
        maximum_nodes: *maximum_nodes,
        maximum_depth: *maximum_depth,
        maximum_owned_backing_bytes: *maximum_owned_backing_bytes,
        maximum_tree_entries: *maximum_tree_entries,
        maximum_metadata_rows: *maximum_metadata_rows,
        maximum_literal_backing_bytes: *maximum_literal_backing_bytes,
        maximum_content_transfers: *maximum_content_transfers,
        maximum_content_objects: *maximum_content_objects,
        maximum_content_groups: *maximum_content_groups,
        maximum_content_bytes: *maximum_content_bytes,
        maximum_content_metadata_bytes: *maximum_content_metadata_bytes,
        maximum_model_bytes: *maximum_model_bytes,
    }
}
