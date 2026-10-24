//! Counts the independent Source activation graph before any Prepare or claim.
//!
//! Closed sizing views borrow actual pre-Prepare originals. Only the future
//! ContentRef/U64/Bytes grammar is widened. Existing signer validation is added
//! as fresh conservative transient credit; its previously admitted row is never
//! spent again. Native, SDK and other Source owners remain independently summed.

use super::*;
use projection::SigningShapes;

impl PacketCompleteSemanticSource {
    pub(crate) fn original_restoration_activation_source_construction_counter_scratch_data() -> usize
    {
        Self::original_restoration_signer_construction_counter_scratch_data()
            + Self::original_restoration_activation_declaration_counter_scratch_data()
            + NodeRuntime::capture_serialization_counter_scratch_data()
            + CnpSemanticSourceRead::original_fresh_query_call_scratch_data()
            + CnpSemanticSourceRead::original_fresh_query_armed_recheck_counter_scratch_data()
            + CnpController::original_installed_restoration_activation_counter_scratch_data()
            + OriginalInstalledRestorationActivationClaim::counter_scratch_data()
            + original_installed_restoration_activation_construction_counter_scratch_data()
            + restoration_activation_retained_native_evidence_counter_scratch_data()
            + crucible_node_transport::client::original_host_source_json_counter_scratch_data()
            + projection::counter_scratch_data()
            + crucible_node_transport::connection::OriginalNative5FrameHistory::original_canonical_reference_counter_scratch_data()
            + owner::counter_scratch_data()
            + upload::counter_scratch_data()
            + world_content::counter_scratch_data()
            + CnpSemanticSourceRead::original_fresh_query_callback_views_data()
            + crate::node_contract::opaque_owner_counter_scratch_data()
            + construction_data::counter_scratch_data()
            + size_of::<OriginalSourceRestorationActivationConstructionData>()
            + size_of::<Result<OriginalSourceRestorationActivationConstructionData, RuntimeError>>()
            + size_of::<OriginalSourceRestorationActivationVerifiedPhase<'static>>()
            + size_of::<
                Result<OriginalSourceRestorationActivationVerifiedPhase<'static>, RuntimeError>,
            >()
            + size_of::<OriginalInstalledRestorationActivationSigningConstructionInputs<'static>>()
            + size_of::<OriginalInstalledRestorationActivationSigningInputs<'static>>()
            + size_of::<
                crucible_node_transport::client::OriginalRestorationActivationTargetBindingData<
                    'static,
                >,
            >()
            + size_of::<
                Result<
                    crucible_node_transport::client::OriginalRestorationActivationTargetBindingData<
                        'static,
                    >,
                    crucible_node_transport::ProviderError,
                >,
            >()
            + size_of::<
                Result<
                    std::cell::Ref<'static, Option<OriginalAckPeerAssociation>>,
                    std::cell::BorrowError,
                >,
            >()
            + size_of::<
                Result<
                    std::cell::RefMut<'static, Option<OriginalAckPeerAssociation>>,
                    std::cell::BorrowMutError,
                >,
            >()
            + size_of::<
                Result<
                    std::cell::Ref<'static, Option<OriginalAckPeerBirth>>,
                    std::cell::BorrowError,
                >,
            >()
            + size_of::<std::cell::Ref<'static, Option<OriginalAckPeerAssociation>>>()
            + size_of::<std::cell::RefMut<'static, Option<OriginalAckPeerAssociation>>>()
            + size_of::<std::cell::Ref<'static, Option<OriginalAckPeerBirth>>>()
            + size_of::<PacketRestorationActivationRequest>()
            + size_of::<PacketRestorationActivationContext>()
            + size_of::<PacketRestorationActivationArtifact>()
            + size_of::<PacketNativeRestoredCommitHold>()
            + size_of::<crucible_node_format::ActivationManifest>()
            + size_of::<Result<crucible_node_format::ActivationManifest, serde_json::Error>>()
            + size_of::<crucible_node_transport::bodies::WorldActivateRequest>()
            + size_of::<
                Result<crucible_node_transport::bodies::WorldActivateRequest, serde_json::Error>,
            >()
            + size_of::<serde_json::Map<String, serde_json::Value>>()
            + size_of::<Result<serde_json::Value, serde_json::Error>>()
            + size_of::<
                Option<(
                    PacketRestorationActivationRequest,
                    Id,
                    OriginalInstalledRestorationActivationConstructionData,
                    Option<world_content::WorldUploadBodies>,
                )>,
            >()
            + size_of::<
                Result<
                    (
                        PacketRestorationActivationRequest,
                        Id,
                        OriginalInstalledRestorationActivationConstructionData,
                        Option<world_content::WorldUploadBodies>,
                    ),
                    RuntimeError,
                >,
            >()
            + size_of::<Result<(ContentRef, PacketNativeRestoredCommitHold), RuntimeError>>()
            + size_of::<Result<PacketNative5UnderlyingRecord, crucible_node_transport::ProviderError>>(
            )
            + size_of::<Result<PacketRestorationActivationRequest, RuntimeError>>()
            + size_of::<Result<PacketRestorationActivationArtifact, serde_json::Error>>()
            + size_of::<Result<PacketRestorationActivationRequest, serde_json::Error>>()
            + size_of::<Result<PacketNativeRestoredRecord, serde_json::Error>>()
            + size_of::<Result<PacketNativeRestoredCommitHold, serde_json::Error>>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + size_of::<[u8; 32]>()
            + size_of::<[u8; 8]>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<bool, RuntimeError>>()
            // Complete cursors for every actual fixed numeric sum, rather
            // than an unrelated scalar-array payload as a header substitute.
            + size_of::<std::array::IntoIter<usize, 2>>()
            + size_of::<std::array::IntoIter<usize, 3>>()
            + size_of::<std::array::IntoIter<usize, 4>>()
            + size_of::<std::array::IntoIter<usize, 5>>()
            + size_of::<std::array::IntoIter<usize, 6>>()
            + size_of::<std::array::IntoIter<usize, 7>>()
            + size_of::<std::array::IntoIter<usize, 10>>()
            + size_of::<std::array::IntoIter<usize, 15>>()
            + size_of::<[PacketRestorationActivationPhase; 2]>()
            + size_of::<
                std::iter::Enumerate<std::array::IntoIter<PacketRestorationActivationPhase, 2>>,
            >()
            + size_of::<
                std::iter::Zip<
                    std::array::IntoIter<&'static Id, 2>,
                    std::array::IntoIter<&'static str, 2>,
                >,
            >()
    }

    /// Quotes separately retained signing originals and complete evidence work.
    ///
    /// This visitor constructs no request, scope, future proof, hash or grant.
    /// The opaque Window must admit every independent owner before Prepare.
    ///
    /// # Errors
    /// Refuses another Source/controller/selected target, a used activation
    /// attempt, stale original Query, malformed originals or checked exhaustion.
    pub(crate) fn original_restoration_activation_source_construction_data(
        &self,
        inputs: &OriginalInstalledRestorationActivationSigningConstructionInputs<'_>,
        maximum: usize,
    ) -> Result<OriginalSourceRestorationActivationConstructionData, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if !self.is_original_restoration_activation_declaration_data()? {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let fixed =
            Self::original_restoration_activation_source_construction_counter_scratch_data();
        if fixed > maximum || !std::ptr::eq(self, inputs.transfer.source.as_ref()) {
            return Err(RuntimeError::ResourceLimit);
        }
        self.authenticate_transfer_selection_data()?;
        inputs
            .transfer
            .ticket
            .authenticate_source(inputs.transfer.archive)?;
        let controller = inputs.transfer.controller;
        let target = controller
            .original_installed_restoration_activation_target_binding_data()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let installation = self.installation();
        if target.owner_binding != &installation.owner
            || target.node != &installation.binding.compatibility.node_id
            || target.owner != &installation.owner.owner.id
            || target.admission != &installation.admission
            || target.transaction != &installation.transaction
            || target.gate != &installation.gate
            || target.world != &installation.world_binding_hash
            || target.world != &inputs.transfer.activation.world_binding_hash
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        for (id, prefix) in inputs
            .request_ids
            .into_iter()
            .zip(["cnp-activate-", "cnp-world-activate-"])
        {
            if id.as_str().strip_prefix(prefix)
                != Some(inputs.transfer.activation.activation_id.as_str())
            {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        original.authenticate_transfer_ready_data()?;
        if original.restoration_activation.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        let emitter = original
            .emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        inputs
            .transfer
            .query
            .authenticate_original_source_context_data(controller, emitter, &installation.owner)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let frame = usize::try_from(controller.authority().limits().frame_bytes.get())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let shapes = projection::measure(inputs, &target, maximum)?;
        let mut retained = OriginalSourceRestorationActivationAttempt::minimum_bank_bytes(frame)?;
        let mut transient = 0usize;
        let mut scratch = fixed;
        for (index, phase) in [
            PacketRestorationActivationPhase::Arm,
            PacketRestorationActivationPhase::WorldActivate,
        ]
        .into_iter()
        .enumerate()
        {
            // The four independently retained normalized owners use their own
            // closed dynamic backing. SDK originals are not a Source bank.
            retained = sum(
                [
                    retained,
                    shapes.request.backing,
                    shapes.artifact.backing,
                    shapes.assigned[index].backing,
                    shapes.terminal[index].backing,
                    inputs
                        .activation_data
                        .source_evidence_retained_requested_bytes_data(phase),
                ],
                maximum,
            )?;
            transient = sum(
                [
                    transient,
                    shapes.phase_work(index, maximum)?,
                    inputs
                        .activation_data
                        .source_evidence_maximum_simultaneous_transient_bytes_data(phase),
                    // These two independent old validation invocations authenticate
                    // current committed history and its held continuation. Pricing
                    // the old whole graph is conservative; no old credit is reused.
                    inputs.signer.requested_peak_bytes_data(),
                    inputs.signer.requested_peak_bytes_data(),
                ],
                maximum,
            )?;
            scratch = sum(
                [
                    scratch,
                    inputs
                        .activation_data
                        .source_evidence_counter_scratch_bytes_data(phase),
                ],
                maximum,
            )?;
        }
        // Source owns these complete content copies independently of the
        // Window publication and SDK cache. No upload credit is borrowed from
        // the old Commit signer or from an unsigned future native grant.
        let coordinator = inputs.coordinator.maximum_encoded_bytes_data();
        let manifest = inputs
            .coordinator
            .maximum_activation_manifest_encoded_bytes_data();
        if coordinator
            > inputs.activation_data.upload_maximum_content_bytes_data(
                PacketRestorationActivationUploadRole::Coordinator,
            )
            || manifest
                > inputs.activation_data.upload_maximum_content_bytes_data(
                    PacketRestorationActivationUploadRole::Manifest,
                )
        {
            return Err(RuntimeError::ResourceLimit);
        }
        retained = sum(
            [
                retained,
                coordinator,
                manifest,
                projection::future_reference_backing_data(maximum)?,
                projection::future_reference_backing_data(maximum)?,
            ],
            maximum,
        )?;
        // Actual Manifest construction, Value and bounded canonical work are
        // a new Source phase; Names' original owner's allowance is not reused.
        transient = sum(
            [
                transient,
                inputs
                    .coordinator
                    .activation_manifest_retained_requested_bytes_data(),
                inputs
                    .coordinator
                    .activation_manifest_maximum_simultaneous_transient_bytes_data(),
            ],
            maximum,
        )?;
        for role in [
            PacketRestorationActivationUploadRole::Coordinator,
            PacketRestorationActivationUploadRole::Manifest,
        ] {
            if inputs.activation_data.upload_chunk_bytes_data(role) == 0
                || inputs.activation_data.upload_maximum_frame_bytes_data(role) != frame
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            retained = sum(
                [
                    retained,
                    shapes.upload.request.backing,
                    shapes.upload.artifact.backing,
                    shapes.upload.assigned.backing,
                    shapes.upload.terminal.backing,
                ],
                maximum,
            )?;
            transient = sum([transient, shapes.upload.phase_work(maximum)?], maximum)?;
        }
        // The historical Hold is parsed again beside the revalidated native
        // owner. This independent upper includes its closed typed decoder and
        // canonical work already present in the complete old signer graph.
        transient = sum(
            [
                transient,
                inputs.signer.requested_peak_bytes_data(),
                inputs
                    .coordinator
                    .activation_manifest_retained_requested_bytes_data(),
                inputs
                    .coordinator
                    .activation_manifest_maximum_simultaneous_transient_bytes_data(),
                original
                    .native
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .original_fresh_current_storage_data()?,
            ],
            maximum,
        )?;
        scratch = sum(
            [
                scratch,
                inputs
                    .coordinator
                    .activation_manifest_counter_scratch_bytes_data(),
            ],
            maximum,
        )?;
        let requested = sum([retained, transient, scratch], maximum)?;
        inputs
            .transfer
            .query
            .authenticate_current(controller, emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        Ok(OriginalSourceRestorationActivationConstructionData {
            process: std::process::id(),
            thread: std::thread::current().id(),
            source: self,
            controller,
            provider: *inputs.activation_data,
            retained,
            transient,
            scratch,
            requested,
            maximum,
            frame,
            manifest: inputs
                .coordinator
                .maximum_activation_manifest_encoded_bytes_data(),
        })
    }
}

impl SigningShapes {
    fn phase_work(&self, index: usize, maximum: usize) -> Result<usize, RuntimeError> {
        let request_validation = self.request.serialization;
        let context_validation = sum([request_validation, self.context.serialization], maximum)?;
        let create_proof = sum(
            [
                context_validation,
                self.context.serialization,
                size_of::<PacketRestorationActivationProof>(),
                "source-owned.packet-restoration-activation-proof/1".len(),
                "blake3-256-mac".len(),
                32,
                32,
            ],
            maximum,
        )?;
        let verify_proof = sum([context_validation, create_proof, 32], maximum)?;
        let saved_pair = sum(
            [
                self.assigned[index].serialization,
                self.terminal[index].serialization,
                self.artifact
                    .decode::<PacketRestorationActivationArtifact>(maximum)?,
                self.request
                    .decode::<PacketRestorationActivationRequest>(maximum)?,
                request_validation,
                self.assigned[index].serialization,
                verify_proof,
            ],
            maximum,
        )?;
        // Sum complete named phases conservatively. Matching phase labels do
        // not permit native/other-owner transient reuse or erase old partials.
        sum(
            [
                self.request
                    .decode::<PacketRestorationActivationRequest>(maximum)?,
                self.scope.serialization,
                self.request.serialization,
                self.assigned[index].serialization,
                self.request
                    .decode::<PacketRestorationActivationRequest>(maximum)?,
                create_proof,
                self.artifact.serialization,
                self.assigned[index].serialization,
                self.request
                    .decode::<PacketRestorationActivationRequest>(maximum)?,
                self.terminal[index].serialization,
                saved_pair,
                self.artifact
                    .decode::<PacketRestorationActivationArtifact>(maximum)?,
                self.scope.serialization,
                // Read-only World inspection owns a copied baseline body while
                // reconstructing its typed request. The complete envelope upper
                // dominates that body; the full manifest decoder is separate.
                self.assigned[index].serialization,
                saved_pair,
            ],
            maximum,
        )
    }
}

impl projection::UploadShapes {
    fn phase_work(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let context_validation = sum(
            [self.request.serialization, self.context.serialization],
            maximum,
        )?;
        let create_proof = sum(
            [
                context_validation,
                self.context.serialization,
                size_of::<PacketRestorationActivationProof>(),
                "source-owned.packet-restoration-activation-upload-proof/1".len(),
                "blake3-256-mac".len(),
                32,
                32,
            ],
            maximum,
        )?;
        let verify_proof = sum([context_validation, create_proof, 32], maximum)?;
        let saved = sum(
            [
                self.assigned.serialization,
                self.terminal.serialization,
                self.artifact
                    .decode::<PacketRestorationActivationUploadArtifact>(maximum)?,
                self.request
                    .decode::<PacketRestorationActivationUploadRequest>(maximum)?,
                self.request.serialization,
                self.assigned.serialization,
                verify_proof,
            ],
            maximum,
        )?;
        // These complete closed phases remain additive; no serial-phase refund
        // is inferred for other native owners or retained failed partials.
        sum(
            [
                self.request
                    .decode::<PacketRestorationActivationUploadRequest>(maximum)?,
                self.request.serialization,
                self.assigned.serialization,
                self.request
                    .decode::<PacketRestorationActivationUploadRequest>(maximum)?,
                create_proof,
                self.artifact.serialization,
                self.assigned.serialization,
                saved,
                self.artifact
                    .decode::<PacketRestorationActivationUploadArtifact>(maximum)?,
                self.terminal.serialization,
            ],
            maximum,
        )
    }
}
