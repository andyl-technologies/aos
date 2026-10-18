//! Retains Source arguments before each fallible Capture17 construction step.

use super::super::{
    construction_data::OriginalSourceRestoredCaptureConstructionData as Row,
    effect::FrozenCheckpoint,
};
use super::*;
use crate::node_adapters::cnp::CnpSemanticSource;
use crucible_node_contract::{Extensions, Validate, canonical};
use crucible_node_provider::envelope::Nullable;
use crucible_node_provider::{
    bodies::{BeginKind, BeginRequest, CaptureArguments},
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

impl CaptureOnceOwner {
    pub(in super::super) fn freeze_current17_data(
        &mut self,
        record: &PacketNativeRestoredRecord,
        underlying: &PacketNative5UnderlyingRecord,
        measurement: &ContentRef,
        first: &ContentRef,
        scope: &PacketRestorationActivationScope,
        frontier: U64,
    ) -> Result<(), RuntimeError> {
        if self.stage != Stage::Unused
            || self.construction.started
            || self.construction.frozen.is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.construction.started = true;
        self.construction.frozen = Some(FrozenCheckpoint {
            record: super::super::effect::clone_restored_record_data(record),
            underlying: super::super::effect::clone_underlying_record_data(underlying),
            measurement: measurement.clone(),
            first_observation: first.clone(),
            scope: scope.clone(),
            frontier,
        });
        Ok(())
    }

    pub(in super::super) fn build_and_run_current17_data(
        &mut self,
        source: &PacketCompleteSemanticSource,
        controller: &mut CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        inputs: &OriginalRestoredCaptureSigningInputs<'_>,
        claim: &OriginalRestoredCaptureClaim<'_>,
        launch: &PacketNative5SourceLaunch,
        raw5: &[u8],
        row: &Row,
        key: &[u8; 32],
        recheck: &mut dyn FnMut() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        if self.stage != Stage::Prepared
            || !self.construction.started
            || self.construction.capture.is_some()
            || self.transport.is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        claim.authenticate_current_data(source, controller)?;

        let ancestry = self
            .construction
            .ancestry
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let frozen = self
            .construction
            .frozen
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        // Prefix preparation must leave the exact saved SDK frontier untouched.
        if controller
            .original_restored_settled_capture_history_next_sequence_data(emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?
            != frozen.frontier
            || ancestry.first_observation != frozen.first_observation
        {
            return Err(RuntimeError::ForeignAuthority);
        }

        let (checkpoint, checkpoint_bytes) = claim.coordinator_checkpoint_data()?;
        if checkpoint_bytes.len() > row.checkpoint {
            return Err(RuntimeError::ResourceLimit);
        }

        let prefix = self.prefix.payload_data()?;
        // Recompute under the genuine retained startup loan before any owning
        // request is built. A copied carrier, output-only allowance or generic
        // ingress row cannot substitute for these complete future phase axes.
        let native_upload =
            source.with_original_completed_restored_settled_startup_data(|storage| {
                storage
                    .source_upload_future_storage_data(launch, raw5)
                    .map_err(|_| RuntimeError::ResourceLimit)
            })?;
        if native_upload != row.native_upload {
            return Err(RuntimeError::ForeignAuthority);
        }
        native_upload
            .authenticate_content_bounds_data([
                prefix.1.len(),
                claim.runtime_object_data().bytes.len(),
            ])
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let installation = source.installation();
        self.construction.capture = Some(PacketRestoredSettledCaptureRequest {
            schema: RESTORED_SETTLED_CAPTURE_REQUEST.into(),
            scope: frozen.scope.clone(),
            capture: CaptureArguments {
                capture_id: claim.ticket_data().capture_id().clone(),
                participant_ids: claim.ticket_data().participants().to_vec(),
                cut_id: claim.ticket_data().capture_id().clone(),
                cut: claim.ticket_data().cut(),
                event_ordinal: claim.ticket_data().ordinal(),
                ordering_profile: installation
                    .binding
                    .compatibility
                    .operating_contract
                    .ordering_profile
                    .clone(),
                preservation_contract: Id::new(
                    crucible_node_provider::reference_packet::continuation_contracts::PACKET_COMPLETE_LINEAGE_PROFILE,
                )
                .map_err(|_| RuntimeError::InvalidReceipt)?,
            },
            capture_owner: claim.ticket_data().owner().owner.clone(),
            capture_operation: claim.capture_operation_data().clone(),
            runtime_object: claim.runtime_object_data().reference.clone(),
            coordinator_checkpoint: checkpoint.clone(),
            parent_archive: ancestry.parent_archive_index.clone(),
            first_observation: frozen.first_observation.clone(),
            current_record: frozen.measurement.clone(),
            current_model: frozen.record.native_receipt.native_record.clone(),
            history_prefix: prefix.0.clone(),
            history_next_sequence: frozen.frontier,
            native_schema: source
                .original_restored_settled_capture_schema_data()
                .map_err(|_| RuntimeError::ForeignAuthority)?
                .definition
                .clone(),
            native_allocation: row.native.actions,
        });
        let request = self
            .construction
            .capture
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        request
            .validate_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;

        self.construction.arguments =
            Some(serde_json::to_value(&request.capture).map_err(|_| RuntimeError::InvalidReceipt)?);
        self.construction.body = Some(BeginRequest {
            kind: BeginKind::Capture,
            binding_hash: installation
                .owner
                .identity()
                .map_err(|_| RuntimeError::InvalidReceipt)?,
            owner_generation: installation.binding.authority.owner_generation,
            activation_id: Nullable(Some(inputs.world.record().activation_id.clone())),
            world_generation: inputs.world.record().generation,
            arguments: self
                .construction
                .arguments
                .as_ref()
                .and_then(|v| v.as_object())
                .cloned()
                .ok_or(RuntimeError::InvalidReceipt)?,
            extensions: Extensions::new(),
        });

        for role in 0..4 {
            self.construction.ids[role] = Some(routing_id_data(
                claim.ticket_data().capture_id(),
                &installation.binding.compatibility.node_id,
                u8::try_from(role).map_err(|_| RuntimeError::ResourceLimit)?,
            )?);
        }

        for index in 0..2 {
            let (ordinal, reference) = if index == 0 {
                (
                    PacketRestoredSettledCaptureUploadOrdinal::HistoryPrefix,
                    prefix.0,
                )
            } else {
                (
                    PacketRestoredSettledCaptureUploadOrdinal::RuntimeObject,
                    &claim.runtime_object_data().reference,
                )
            };
            self.construction.uploads[index] = Some(PacketRestoredSettledCaptureUploadRequest {
                schema: "source-owned.packet-restored-settled-capture-upload-request/17".into(),
                capture: request.clone(),
                ordinal,
                transfer_id: self.construction.ids[index + 2]
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .clone(),
                content: reference.clone(),
                native_allocation: row.native_upload.per_original_requested_axes_data(),
            });
        }

        let body = self
            .construction
            .body
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        row.sdk
            .authenticate_inputs_data(controller, launch, request, body)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        for request in self.construction.uploads.iter().flatten() {
            request
                .validate_data()
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            row.sdk
                .authenticate_typed_owner_data(
                    &crucible_node_provider::client::RestoredSettledCaptureTypedOwnerData::UploadRequest(
                        request,
                    ),
                )
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }

        let geometry = original_restored_settled_capture_auxiliary_geometry_for_lengths_data(
            &controller.authority().limits(),
            [prefix.1.len(), claim.runtime_object_data().bytes.len()],
            usize::try_from(launch.limits.requests.get())
                .map_err(|_| RuntimeError::ResourceLimit)?,
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        // The original frozen owner remains in the Source even if the real SDK
        // refuses. This independent verifier loan is a separately prepaid T copy.
        let frozen = self
            .construction
            .frozen
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .clone();
        let confirmation = self.construction.ids[1]
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .clone();
        let transport = CaptureSdkOwners::new_data(
            self.construction.ids[0]
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .clone(),
            claim.capture_operation_data().clone(),
            body.clone(),
            request.clone(),
            [
                self.construction.uploads[0]
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .clone(),
                self.construction.uploads[1]
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .clone(),
            ],
            crate::node_scheduling::InputPayload {
                reference: prefix.0.clone(),
                bytes: prefix.1.to_vec(),
            },
            claim.runtime_object_data().clone(),
        );
        self.run_data(
            transport,
            source,
            controller,
            emitter,
            inputs,
            claim,
            launch,
            raw5,
            confirmation,
            &row.sdk,
            &geometry,
            &row.native.output_limits,
            &row.validation,
            &frozen.record,
            &frozen.underlying,
            &frozen.measurement,
            frozen.frontier,
            key,
            recheck,
        )
    }

    pub(in super::super) fn retain_final_semantic17_data(
        &mut self,
        value: serde_json::Value,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        self.current_bridge_data()?;
        if !self.construction.final_started || self.construction.final_value.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.construction.final_value = Some(value);
        let value = self
            .construction
            .final_value
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let prefix = self.prefix.semantic_value17_data()?;
        authenticate_unchanged_semantic_fields_data(prefix, value)?;
        self.construction.final_bytes =
            canonical::canonical_json(value).map_err(|_| RuntimeError::InvalidReceipt)?;
        if self.construction.final_bytes.len() > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        self.construction.final_reference = Some(
            canonical::content_ref(
                &self.construction.final_bytes,
                crucible_node_provider::protocol_snapshot::restored_journal17::RESTORED_SETTLED_SEMANTIC17_MEDIA,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?,
        );

        // Encode the exact retained embedded DOM. Serializing NodeHistory again
        // could change alias ordinals or first-definition rows between passes.
        self.construction.node_bytes =
            canonical::canonical_json(value.get("node").ok_or(RuntimeError::InvalidReceipt)?)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        if self.construction.node_bytes.len() > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        self.construction.node_reference = Some(
            canonical::content_ref(&self.construction.node_bytes, "application/json")
                .map_err(|_| RuntimeError::InvalidReceipt)?,
        );
        Ok(())
    }
}

fn routing_id_data(capture: &Id, node: &Id, role: u8) -> Result<Id, RuntimeError> {
    let mut hash = blake3::Hasher::new_derive_key("source.capture17-routing/1");
    for bytes in [capture.as_str().as_bytes(), node.as_str().as_bytes()] {
        hash.update(
            &u64::try_from(bytes.len())
                .map_err(|_| RuntimeError::ResourceLimit)?
                .to_le_bytes(),
        );
        hash.update(bytes);
    }
    hash.update(&[role]);
    let mut text = String::new();
    text.try_reserve_exact(128)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    text.push_str("source-capture17-");
    let digest = hash.finalize();
    let hexadecimal = b"0123456789abcdef";
    for byte in digest.as_bytes() {
        text.push(hexadecimal[usize::from(*byte >> 4)] as char);
        text.push(hexadecimal[usize::from(*byte & 15)] as char);
    }
    Id::new(text).map_err(|_| RuntimeError::InvalidReceipt)
}

// Compares historical DATA only. The actual caller separately requires its
// private completed Bridge and Source writer before either operand reaches it.
fn authenticate_unchanged_semantic_fields_data(
    before: &serde_json::Value,
    after: &serde_json::Value,
) -> Result<(), RuntimeError> {
    for key in ["schema", "ancestry", "node"] {
        if before.get(key) != after.get(key) {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    let before = before
        .get("source")
        .and_then(|v| v.as_object())
        .ok_or(RuntimeError::InvalidReceipt)?;
    let after = after
        .get("source")
        .and_then(|v| v.as_object())
        .ok_or(RuntimeError::InvalidReceipt)?;
    if before.len() != 11 || after.len() != 11 {
        return Err(RuntimeError::InvalidReceipt);
    }
    for (key, old) in before {
        if key != "capture" && after.get(key) != Some(old) {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_adapters::cnp::CnpSemanticSource;
    use crucible_node_provider::envelope::Nullable;
    use serde_json::json;

    #[test]
    fn every_modeled_prefix_field_remains_equal_across_administrative_capture() {
        // These are inert DATA comparands, never original owners or a proof
        // that the abbreviated JSON is a valid Source/Node completion.
        let before = json!({"schema":"semantic/17","ancestry":{"parent":"original"},
            "node":{"aliases":[["definition",0],["alias",0]]},"source":{
                "schema":"source/17","installation":{"original":1},"world":{"generation":2},
                "once":{"spent":true},"limits":{"producer_used":3},
                "first_observation":{"immutable":1},"producer":[1,2,3],
                "current_observations":[],"input_history":null,
                "capture":{"phase":"preparing"},"inherited":{"exact":"parent"}}});
        let mut after = before.clone();
        after["source"]["capture"] = json!({"phase":"complete"});
        assert!(authenticate_unchanged_semantic_fields_data(&before, &after).is_ok());

        for key in before["source"]
            .as_object()
            .unwrap()
            .keys()
            .filter(|key| key.as_str() != "capture")
        {
            let mut changed = after.clone();
            changed["source"][key] = json!({"substituted":key});
            assert!(
                authenticate_unchanged_semantic_fields_data(&before, &changed).is_err(),
                "{key}"
            );
        }
        for key in ["schema", "ancestry", "node"] {
            let mut changed = after.clone();
            changed[key] = json!({"substituted":key});
            assert!(
                authenticate_unchanged_semantic_fields_data(&before, &changed).is_err(),
                "{key}"
            );
        }
        let mut changed = after.clone();
        changed["source"]["future_unmodeled_field"] = json!(true);
        assert!(authenticate_unchanged_semantic_fields_data(&before, &changed).is_err());
    }
}

impl CaptureOnceOwner {
    pub(in super::super) fn current_native_outputs17_data(
        &self,
    ) -> Result<
        &crucible_node_provider::protocol_snapshot::restored_settled17::ValidatedRestoredSettledNative17CaptureOutputs,
        RuntimeError,
    >{
        self.current_bridge_data()?;
        self.post_confirmation.current_native_outputs17_data()
    }
}
